#
#
#

from argparse import ArgumentError
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import StringIO
from itertools import islice
from logging import getLogger
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

        buf.write('```')

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

        buf.write('```')


class RipeException(Exception):
    pass


class NoProbes(RipeException):
    pass


class RipeHandler(BaseSlashHandler):
    log = getLogger('RipeHandler')

    command = 'ripe'

    executor = ThreadPoolExecutor(max_workers=4)

    def initialize(self, ripe_client, time_fmt='%Y-%m-%dT%H:%M:%SZ', **kwargs):
        super(RipeHandler, self).initialize(**kwargs)

        self.ripe_client = ripe_client
        self.time_fmt = time_fmt

    def handle(self, options, args):
        self.log.debug('handle: options=%s', options)

        func = {
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
        self.log.debug('_select_probes: options=%s', options)

        radius = options.radius_miles * 1.60934 \
            if options.radius_miles is not None else options.radius

        kwargs = {}

        # ASN
        if options.asn_v4 is not None:
            kwargs['asn_v4'] = options.asn_v4
        elif options.asn_v6 is not None:
            kwargs['asn_v6'] = options.asn_v6

        # TODO: filter out bad probes
        probes = self.ripe_client.probes_by_geo(options.lat, options.lon,
                                                radius, **kwargs)
        probe_ids = [p['id'] for p in islice(probes, options.num_probes)]
        self.log.debug('_select_probes: n=%d, probe_ids=%s', len(probe_ids),
                       probe_ids)

        if len(probe_ids) == 0:
            raise NoProbes('Failed to find probes in the requested area')

        return probe_ids

    def _sslcert(self, options):
        self.log.debug('_sslcert: options=%s', options)

        probe_ids = self._select_probes(options)

        measurement_id = self.ripe_client.sslcert(options.target, probe_ids)

        self.send_simple_response('Measurement started '
                                  'https://atlas.ripe.net/measurements/{}/'
                                  .format(measurement_id))

        self.log.debug('_sslcert: waiting %ds before proceeding',
                       options.min_wait)
        sleep(options.min_wait)

        self._send_sslcert_response(options.min_wait, options.max_wait,
                                    measurement_id)

    def _send_sslcert_response(self, min_wait, max_wait, measurement_id):
        self.log.debug('_send_sslcert_response: min_wait=%d, max_wait=%d, '
                       'measurement_id=%d', measurement_id)

        measurement = self.ripe_client.measurement(measurement_id)
        probes_scheduled = measurement['probes_scheduled']

        time_remaining = max_wait - min_wait
        results = list(self.ripe_client.results(measurement_id))
        while time_remaining > 0:
            self.log.debug('_send_sslcert_response: %d >= %d, '
                           'time_remaining=%d', len(results), probes_scheduled,
                           time_remaining)
            if len(results) >= probes_scheduled:
                break

            # another round
            time_remaining -= 30
            sleep(min(time_remaining, 30))

            results = list(self.ripe_client.results(measurement_id))

        # Refresh the measurement info in case anything has changed since we
        # looked
        measurement = self.ripe_client.measurement(measurement_id)

        buf = StringIO()

        buf.write('Target: ')
        buf.write(measurement['target'])
        buf.write('\n')

        buf.write('Start: ')
        start = datetime.utcfromtimestamp(measurement['start_time'])
        buf.write(start.strftime(self.time_fmt))
        buf.write('\n')

        buf.write('Status: ')
        buf.write(measurement['status']['name'])
        buf.write('\n')

        buf.write('Probes: ')
        buf.write(str(measurement['probes_requested']))
        buf.write(' requested, ')
        buf.write(str(measurement['probes_scheduled']))
        buf.write(' scheduled, ')
        buf.write(str(measurement['participant_count']))
        buf.write(' participating\n')

        buf.write('Details: https://atlas.ripe.net/measurements/')
        buf.write(str(measurement_id))
        buf.write('/\n')


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
            'Tt Resolve',
            'Tt Connect',
            'Tt Response',
        ))
        for result in results:

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

        table.write(buf)

        self.send_simple_response(buf.getvalue())

    def get_parser(self):
        parser = super(RipeHandler, self).get_parser()

        parser.add_argument('command', choices=('sslcert',),
                            help='The measurement type to run')
        parser.add_argument('--target', help='The target of the measurement')
        parser.add_argument('--lat', type=float,
                            help='Probe selection latitude')
        parser.add_argument('--lon', type=float,
                            help='Probe selection longitude')
        parser.add_argument('--radius', type=float, default=40.0,
                            help='Probe selection radius')
        parser.add_argument('--radius-miles', type=float, default=None,
                            help='Probe selection radius in miles')
        parser.add_argument('--address-family', type=int, choices=(4,6),
                            default='4')
        parser.add_argument('--asn-v4', type=int, default=None,
                            help='Probe selection v4 ASN')
        parser.add_argument('--asn-v6', type=int, default=None,
                            help='Probe selection v6 ASN')
        parser.add_argument('--num-probes', type=int, default=20,
                            help='Maximum number of probes to use')
        parser.add_argument('--min-wait', type=int, default=30,
                            help='Minimum number of seconds to wait before '
                            'checking for results')
        parser.add_argument('--max-wait', type=int, default=300,
                            help='Maximum number of seconds to wait for '
                            'results')

        return parser
