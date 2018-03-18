#
#
#

from asn1crypto import pem, x509
from argparse import ArgumentError
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from geoip2.database import Reader as MaxmindReader
from geoip2.errors import AddressNotFoundError
from io import StringIO
from logging import getLogger
from os.path import isfile
from time import sleep

from botie.handlers.base import BaseSlashHandler


class Table(list):

    def __init__(self, header):
        super(Table, self).__init__()

        self.header = header

    def write(self, buf):
        n = len(self.header)
        for row in self:
            n = max(n, len(row))

        widths = [0] * n
        for i, h in enumerate(self.header):
            widths[i] = len(h)

        for row in self:
            for i, c in enumerate(row):
                widths[i] = max(widths[i], len(c))

        total = sum(widths) + (3 * n) - 1
        buf.write('+')
        buf.write('-' * total)
        buf.write('+\n')

        buf.write('| ')
        for i, h in enumerate(self.header):
            n = len(h)
            buf.write(' ' * (widths[i] - n))
            buf.write(h)
            buf.write(' | ')
        buf.write('\n')

        for row in self:
            buf.write('| ')
            for i, c in enumerate(row):
                n = len(c)
                buf.write(' ' * (widths[i] - n))
                buf.write(c)
                buf.write(' | ')
            buf.write('\n')

        buf.write('+')
        buf.write('-' * total)
        buf.write('+\n')


class RipeException(Exception):
    pass


class NoProbes(RipeException):
    pass


class RipeHandler(BaseSlashHandler):
    log = getLogger('RipeHandler')

    command = 'ripe'

    executor = ThreadPoolExecutor(max_workers=4)
    if isfile('./data/GeoIP2-City.mmdb'):
        city_lookup = MaxmindReader('./data/GeoIP2-City.mmdb')
    else:
        city_lookup = MaxmindReader('./data/GeoLite2-City.mmdb')
    asn_lookup = MaxmindReader('./data/GeoLite2-ASN.mmdb')

    def initialize(self, ripe_client, time_fmt='%Y-%m-%dT%H:%M:%SZ', **kwargs):
        super(RipeHandler, self).initialize(**kwargs)

        self.ripe_client = ripe_client
        self.time_fmt = time_fmt

    def handle(self, options, args):
        self.log.debug('handle: options=%s', options)

        func = {
            'ping': self._ping,
            'sslcert': self._sslcert,
        }[options.command]
        self._run_in_background(func, options)

        self.write_echo()

    def _run_in_background(self, func, *args, **kwargs):

        def caller():
            try:
                func(*args, **kwargs)
            except (ArgumentError, RipeException) as e:
                self.backend.send_error_response(self, str(e))
            except Exception:
                self.backend.send_error_response(self, 'Unexpected error')
                self.log.exception('Unhandled in run_in_background/caller')

        self.executor.submit(caller)

    def _select_probes(self, options):

        kwargs = {}

        kwargs['radius'] = options.radius_miles * 1.60934 \
            if options.radius_miles is not None else options.radius

        # ASN
        if options.asn_v4 is not None:
            kwargs['asn_v4'] = options.asn_v4
        elif options.asn_v6 is not None:
            kwargs['asn_v6'] = options.asn_v6

        if options.ip_address is not None:
            return self._select_probes_ip_address(options, kwargs)
        elif not (options.lat is None and options.lon is None):
            return self._select_probes_lat_lon(options, kwargs)

        raise ArgumentError(None, 'Missing probe selection parameters')

    def _select_probes_ip_address(self, options, kwargs):
        self.log.debug('_select_probes_ip_address: options=%s, kwargs=%s',
                       options, kwargs)

        ip_address = options.ip_address
        try:
            geo = self.city_lookup.city(ip_address)
        except AddressNotFoundError:
            raise RipeException('Unable to locate {}'.format(ip_address))

        lat = geo.location.latitude
        lon = geo.location.longitude

        if options.same_asn:
            try:
                asn = self.asn_lookup.asn(ip_address).autonomous_system_number
            except AddressNotFoundError:
                raise RipeException('Unable to find ASN for {}'
                                    .format(ip_address))
            if '.' in ip_address:
                kwargs['asn_v4'] = asn
            else:
                kwargs['asn_v6'] = asn

        return self._select_probes_lat_lon(options, kwargs, lat, lon)

    def _select_probes_lat_lon(self, options, kwargs, lat=None, lon=None):
        self.log.debug('_select_probes_lat_lon: options=%s, kwargs=%s, '
                       'lat=%s, lon=%s', options, kwargs, lat, lon)

        if lat is None:
            lat = options.lat
        if lon is None:
            lon = options.lon

        probe_ids = []
        for probe in self.ripe_client.probes_by_geo(lat, lon, **kwargs):
            if probe['status']['id'] == 1:
                probe_ids.append(probe['id'])
            if len(probe_ids) >= options.num_probes:
                break

        self.log.debug('_select_probes: n=%d, probe_ids=%s', len(probe_ids),
                       probe_ids)

        if len(probe_ids) == 0:
            raise NoProbes('Failed to find any probes in the requested area')

        return probe_ids

    def _await_results(self, options, measurement_id, response_func):
        self.log.debug('_await_results: waiting %ds before proceeding',
                       options.min_wait)
        sleep(options.min_wait)

        measurement = self.ripe_client.measurement(measurement_id)
        probes_scheduled = measurement['probes_scheduled']

        time_remaining = options.max_wait - options.min_wait
        results = list(self.ripe_client.results(measurement_id))
        while time_remaining > 0:
            self.log.debug('_await_results: %d >= %d, '
                           'time_remaining=%d', len(results), probes_scheduled,
                           time_remaining)
            if len(results) >= probes_scheduled:
                break

            # another round
            time_remaining -= 30
            sleep(min(time_remaining, 30))

            results = list(self.ripe_client.results(measurement_id))

        response_func(measurement_id, results)

    def _measurement_summary(self, measurement, buf):
        buf.write('*Target*: ')
        buf.write(measurement['target'])
        buf.write('\n')

        buf.write('*Start*: ')
        start = datetime.utcfromtimestamp(measurement['start_time'])
        buf.write(start.strftime(self.time_fmt))
        buf.write('\n')

        buf.write('*Status*: ')
        buf.write(measurement['status']['name'])
        buf.write('\n')

        buf.write('*Probes*: ')
        buf.write(str(measurement['probes_requested']))
        buf.write(' requested, ')
        buf.write(str(measurement['probes_scheduled']))
        buf.write(' scheduled, ')
        buf.write(str(measurement['participant_count']))
        buf.write(' participating\n')

        buf.write('*Details*: https://atlas.ripe.net/measurements/')
        buf.write(str(measurement['id']))
        buf.write('/\n')

    def _ping(self, options):
        self.log.debug('_ping: options=%s', options)

        if options.measurement_id is not None:
            self._send_ping_response(options.measurement_id)
            return

        probe_ids = self._select_probes(options)

        measurement_id = self.ripe_client.ping(options.target, probe_ids,
                                               options.packets,
                                               options.packet_interval,
                                               options.address_family,
                                               options.resolve_on_probe)

        self.send_simple_response('Measurement started '
                                  'https://atlas.ripe.net/measurements/{}/, '
                                  'waiting up to {}s for it to complete'
                                  .format(measurement_id, options.max_wait))

        self._await_results(options, measurement_id,
                            self._send_ping_response)

    def _send_ping_response(self, measurement_id, results=None):
        self.log.debug('_send_ping_response: measurement_id=%d, results=*',
                       measurement_id)

        if results is None:
            results = list(self.ripe_client.results(measurement_id))

        # Refresh the measurement info in case anything has changed since we
        # looked
        measurement = self.ripe_client.measurement(measurement_id)

        buf = StringIO()

        self._measurement_summary(measurement, buf)

        asn_key = 'asn_v{}'.format(measurement['af'])
        probe_ids = [r['prb_id'] for r in results]
        asns = {
            p['id']: p[asn_key]
            for p in self.ripe_client.probes_by_id(probe_ids)
        }

        table = Table((
            'Source IP',
            'Source AS',
            'Dest IP',
            'Tt Resolve',
            'Packets',
            'Min',
            'Max',
            'Avg',
        ))
        for result in results:

            try:
                ttr = '{:0.2f}'.format(result['ttr'])
            except KeyError:
                ttr = ''

            try:
                _min = '{:0.2f}'.format(result['min'])
            except KeyError:
                _min = ''

            try:
                _max = '{:0.2f}'.format(result['max'])
            except KeyError:
                _max = ''

            try:
                avg = '{:0.2f}'.format(result['avg'])
            except KeyError:
                avg = ''

            sent = result['sent']
            rcvd = result['rcvd']

            percent = 100 * rcvd / sent if sent > 0 else 0
            table.append((
                result['from'],
                str(asns[result['prb_id']]),
                result['dst_addr'],
                ttr,
                '{} of {} = {:0.2f}%'.format(rcvd, sent, percent),
                _min,
                _max,
                avg,
            ))

        def keyer(row):
            try:
                # sort rt ascending
                return float(row[-1])
            except ValueError:
                # fallback to a huge value
                return 999999

        table.sort(key=keyer)

        buf.write('\n')
        buf.write(self.backend.pre_start)
        table.write(buf)
        buf.write(self.backend.pre_end)
        buf.write('\n')

        buf.write('/cc {}'.format(self.backend.user_mention(self)))

        self.send_simple_response(buf.getvalue())

    def _sslcert(self, options):
        self.log.debug('_sslcert: options=%s', options)

        if options.measurement_id is not None:
            self._send_sslcert_response(options.measurement_id)
            return

        probe_ids = self._select_probes(options)

        measurement_id = self.ripe_client.sslcert(options.target, probe_ids,
                                                  options.address_family,
                                                  options.resolve_on_probe)

        self.send_simple_response('Measurement started '
                                  'https://atlas.ripe.net/measurements/{}/, '
                                  'waiting up to {}s for it to complete'
                                  .format(measurement_id, options.max_wait))

        self._await_results(options, measurement_id,
                            self._send_sslcert_response)

    def _send_sslcert_response(self, measurement_id, results=None):
        self.log.debug('_send_sslcert_response: measurement_id=%d, results=*',
                       measurement_id)

        if results is None:
            results = list(self.ripe_client.results(measurement_id))

        # Refresh the measurement info in case anything has changed since we
        # looked
        measurement = self.ripe_client.measurement(measurement_id)

        buf = StringIO()

        self._measurement_summary(measurement, buf)

        asn_key = 'asn_v{}'.format(measurement['af'])
        probe_ids = [r['prb_id'] for r in results]
        asns = {
            p['id']: p[asn_key]
            for p in self.ripe_client.probes_by_id(probe_ids)
        }

        table = Table((
            'Source IP',
            'Source AS',
            'Dest IP',
            'Version',
            'Serial',
            'Tt Resolve',
            'Tt Connect',
            'Tt Response',
        ))
        certs = {}
        for result in results:

            cert_data = bytes(result['cert'][0], 'ascii')
            if pem.detect(cert_data):
                _, _, der_bytes = pem.unarmor(cert_data)
                cert = x509.Certificate.load(der_bytes)

                cert_serial = hex(cert.serial_number)[2:10]
                certs[cert_serial] = cert

            try:
                ttr = '{:0.2f}'.format(result['ttr'])
            except KeyError:
                ttr = ''

            try:
                ttc = '{:0.2f}'.format(result['ttc'])
            except KeyError:
                ttc = ''

            try:
                rt = '{:0.2f}'.format(result['rt'])
            except KeyError:
                rt = ''

            table.append((
                result['from'],
                str(asns[result['prb_id']]),
                result['dst_addr'],
                '{}/{}'.format(result['method'], result['ver']),
                cert_serial,
                ttr,
                ttc,
                rt
            ))

        def keyer(row):
            try:
                # sort rt ascending
                return float(row[-1])
            except ValueError:
                # fallback to a huge value
                return 999999

        table.sort(key=keyer)

        buf.write('\n')
        buf.write(self.backend.pre_start)
        table.write(buf)
        buf.write(self.backend.pre_end)
        buf.write('\n')

        # https://pyopenssl.readthedocs.io/en/latest/api/crypto.html
        for serial, cert in certs.items():
            buf.write('*----------------------------------------*\n')

            buf.write('*Serial*: ')
            buf.write(serial)
            buf.write('\n')

            subject = cert['tbs_certificate']['subject'].native
            buf.write('*Subject*: ')
            buf.write(subject['organization_name'])
            buf.write('\n')

            issuer = cert['tbs_certificate']['issuer'].native
            buf.write('*Issuer*: ')
            buf.write(issuer['common_name'])
            buf.write('\n')

            validity = cert['tbs_certificate']['validity'].native
            buf.write('*Time period*: ')
            buf.write(validity['not_before'].strftime(self.time_fmt))
            buf.write(' - ')
            buf.write(validity['not_after'].strftime(self.time_fmt))
            buf.write('\n')

            buf.write('*Subject alternative name*: \n')
            for domain in cert.valid_domains:
                buf.write('  - ')
                buf.write(domain)
                buf.write('\n')

        buf.write('*----------------------------------------*\n')

        buf.write('/cc {}'.format(self.backend.user_mention(self)))

        self.send_simple_response(buf.getvalue())

    def get_parser(self):
        parser = super(RipeHandler, self).get_parser()

        parser.add_argument('command', choices=('ping', 'sslcert'),
                            help='The measurement type to run')

        group = parser.add_argument_group('Existing measurements')
        group.add_argument('--measurement-id', type=int, default=None,
                           help='Display results from an existing '
                           'measurement')

        group = parser.add_argument_group('Targeting')
        group.add_argument('--target', help='The target of the measurement')

        group = parser.add_argument_group('Probe count')
        group.add_argument('--num-probes', type=int, default=20,
                           help='Maximum number of probes to use')

        group = parser.add_argument_group('IP based probe selection')
        # TODO: validate ip address
        group.add_argument('--ip-address', default=None,
                           help='The IP address to use when selecting probes')
        group.add_argument('--same-asn', action='store_true', default=False,
                           help='Look for probes with the same ASN as '
                           '--ip-address')

        group = parser.add_argument_group('Lat/Lon probe selection')
        group.add_argument('--lat', type=float, default=None,
                           help='Look for probes centering on latitude')
        group.add_argument('--lon', type=float, default=None,
                           help='Look for probes centering on longitude')

        group = parser.add_argument_group('Filter probes by ASN')
        group.add_argument('--asn-v4', type=int, default=None,
                           help='Probe selection v4 ASN')
        group.add_argument('--asn-v6', type=int, default=None,
                           help='Probe selection v6 ASN')

        group = parser.add_argument_group('Probe selection radius ')
        group.add_argument('--radius', type=float, default=40.0,
                           help='Probe selection radius')
        group.add_argument('--radius-miles', type=float, default=None,
                           help='Probe selection radius in miles')

        group = parser.add_argument_group('General test options')
        group.add_argument('--address-family', type=int, choices=(4, 6),
                           default='4')
        group.add_argument('--resolve-on-probe', action='store_true',
                           default=True, help='Do dns resolution on the probe')

        group = parser.add_argument_group('Ping test options')
        # TODO: restrict range 1-16
        group.add_argument('--packets', type=int, default=4,
                           help='Number of packets to send when pinging')
        # TODO: restrict range 2-300000
        group.add_argument('--packet-interval', type=int, default=1000,
                           help='Interval between packets when pinging')
        # TODO: restrict range 1-2048
        group.add_argument('--size', type=int, default=64,
                           help='ICMP packet size to use')

        group = parser.add_argument_group('Misc options')
        group.add_argument('--min-wait', type=int, default=30,
                           help='Minimum number of seconds to wait before '
                           'checking for results')
        group.add_argument('--max-wait', type=int, default=120,
                           help='Maximum number of seconds to wait for '
                           'results')

        # TODO: blow up for unknown args
        return parser
