#!/usr/bin/env python
#https://wiki.python.org/moin/WorkingWithTime
import json, argparse, logging, sys
import calendar, datetime

def convert_enddate_to_ms(ts):
    """Takes ISO 8601 format(string) and converts into epoch time."""
    dt = datetime.datetime.strptime(ts[:-1],'%Y-%m-%dT%H:%M:%S.%f')-\
        datetime.timedelta(hours=0,
        minutes=0)
    ms = calendar.timegm(dt.timetuple())*1000 + dt.microsecond/1000.0
    return ms

def execute(args):

    with open(args.harfile, 'r') as f:
        har = json.load(f)
    logging.info('HAR file loaded')

    if args.file:
        with open(args.file, 'r') as f:
            tcpTime = json.load(f)
    else:
        tcpTime = json.load(sys.stdin)
    logging.info('tcpdump timing file loaded')


    for i in range(len(har['log']['entries'])):
        entry = har['log']['entries'][i]
        url = entry['request']['url']
        timestamp = convert_enddate_to_ms(entry['startedDateTime'])
        if url not in tcpTime:
            logging.warning('No record found in tcpdump for %s', url)
            continue
        else:
            if len(tcpTime[url]) == 1:
                # the object is fetched only once
                timedata = tcpTime[url][0]['data']
                timings = entry['timings']
                # time in tcp timing is computed based on the timestamp when request is sent
                # time in HAR is computed based on the timestamp when the url of the object is parsed
                # the gap needs to be closed
                gap = max(timings['blocked'], 0) +  max(timings['dns'], 0)\
                        + max(timings['connect'], 0) +  max(timings['send'], 0)
                shift = tcpTime[url][0]['request']*1000 - (timestamp + gap)
                logging.debug("%s has time shift %f", url, shift)
                if abs(shift) > args.threshold:
                    logging.warning('Big time shift %.3f ms in request sent time for %s', shift, url)
                    #continue
                dataTimestamps = []
                for d in timedata:
                    dataTimestamps.append({'timestamp': d + gap + shift})
                timings['dataArrivals'] = dataTimestamps
                entry['timings'] = timings
                har['log']['entries'][i] = entry
            else:
                logging.info("multiple records found for %s, TODO", url)

    if args.output:
        with open(args.output, 'w') as outfile:
            json.dump(har, outfile, indent=4)
    else:
        print json.dumps(har, indent=4)

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Merge the output from HTTP analyzer to HAR file')
    parser.add_argument('-f', '--file', default=None, help='Read from a tcp timing file in JSON format instead of STDIN')
    parser.add_argument('harfile', help='Path to the HAR file')
    parser.add_argument('-o', '--output', default=None, help='Output file path instead of STDOUT')
    parser.add_argument('-t', '--threshold', type=float, default=10.0, help='The threshold (ms) for matching objects.\
                                If the difference of timestamps of the same object in HAR and tcp timing is\
                                beyond the threshold, the record is discarded.')
    parser.add_argument('-q', '--quiet', action='store_true', default=False, help='Only print errors')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print debug info.')
    args = parser.parse_args()

    if args.quiet:
        level = logging.ERROR
    elif args.verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING
    logging.basicConfig(
        format = "%(levelname)s:%(message)s",
        level = level
    )
    execute(args)

if __name__ == '__main__':
    main()
