#!/usr/bin/env python
import copy, json, argparse, logging
try:
    import pyshark
except ImportError as e:
    logging.critical("pyshark module is not found.")
    raise e
from mimetools import Message
from StringIO import StringIO

#HTTP2 stream types
HEADER_TYPE = 1
DATA_TYPE = 0
RESET = 3
PUSH_PROMISE = 5

#HTTP2 header types
METHOD = ':method'
STATUS = ':status'

def autopsy_http2(packet, objects, tcpTimestamps):
    p = packet # for short

    if 'tcp' not in p:
        logging.warning("Detect HTTP2 over none-TCP flow. Packet#%d\n", p.number.int_value)
        return

    tcpStream = int(p.tcp.stream)
    now = float(p.sniff_timestamp)

    if not 'type' in p.http2.field_names:
        # this is the magic packet
        # NOTE: we assume magic does not come along with header and data
        return

    # prepare the container
    if tcpStream not in objects:
        objects[tcpStream] = {}

    called_tcp_track = {} # avoid tracking the same packet for the same streamId again {streamId:return_value}
    for h2Layer in p.layers:
        #loop over all h2 layers
        if 'http2' not in h2Layer.field_names:
            continue
        #loop over all streams in a H2 packet
        for streamType in h2Layer.get_field('type').all_fields:
            #local stream index in this packet
            streamIndex = h2Layer.get_field('type').all_fields.index(streamType)
            #HTTP2 stream id
            streamId = h2Layer.get_field('streamId'.lower()).all_fields[streamIndex].int_value
            # find if HEADER or DATA is here
            if streamType.int_value == HEADER_TYPE:
                # build the header dict
                header = {}
                for fi in range(len(h2Layer.get_field('header').all_fields)):
                    key = h2Layer.get_field('header_name').all_fields[fi].showname_value.strip().lower()
                    value = h2Layer.get_field('header_value').all_fields[fi].showname_value.strip()
                    header[key] = value
                if METHOD in header:
                    # the header is a request header
                    # NOTE: query string is included in :path
                    url = header[':scheme'] + '://' + header[':authority'] + header[':path']
                    # each object should have its own streamId
                    if streamId in objects[tcpStream]:
                        logging.warning("HTTP2 stream identifiers cannot be reused. Packet#%d", p.number.int_value)
                        return
                    # insert a new object entry
                    objects[tcpStream][streamId] = {'Protocol': 'h2', 'method': str(header[METHOD]),\
                                                    'url': url, 'request': now, 'response':0, 'data':[]}
                elif STATUS in header:
                    # this is a response header
                    if streamId not in objects[tcpStream]:
                        logging.warning("Unknown HTTP2 stream identifier. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
                        return
                    objects[tcpStream][streamId]['status'] = int(header[STATUS])
                    if streamId not in called_tcp_track:
                        first = track_down_tcp_segemnts(p, objects, streamId, tcpTimestamps)
                        called_tcp_track[streamId] = first
                    else:
                        # other piece of the same streamId called it already
                        # we still need the response time
                        first = called_tcp_track[streamId]
                    objects[tcpStream][streamId]['response'] = first

                else:
                    logging.warning("Unknown header %s", h2Layer)
            elif streamType.int_value == DATA_TYPE:
                # this is a DATA stream
                if streamId not in objects[tcpStream]:
                    logging.warning("Unknown HTTP2 stream identifier. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
                    return
                if streamId not in called_tcp_track:
                    # no one else in the same streamId tracked the tcp
                    first = track_down_tcp_segemnts(p, objects, streamId, tcpTimestamps)
                    called_tcp_track[streamId] = first
            elif streamType.int_value == PUSH_PROMISE:
                # this is the push promise, should be like a request header
                promisedStreamID = h2Layer.get_field('push_promise_promised_stream_id'.lower()).all_fields[streamIndex].int_value
                # NOTE: the following is the same as request header
                header = {}
                for fi in range(len(h2Layer.get_field('header').all_fields)):
                    key = h2Layer.get_field('header_name').all_fields[fi].showname_value.strip().lower()
                    value = h2Layer.get_field('header_value').all_fields[fi].showname_value.strip()
                    header[key] = value
                url = header[':scheme'] + '://' + header[':authority'] + header[':path']
                # each object should have its own streamId
                if promisedStreamID in objects[tcpStream]:
                    logging.warning("HTTP2 stream identifiers cannot be reused. Packet#%d", p.number.int_value)
                    return
                # insert a new object entry
                objects[tcpStream][promisedStreamID] = {'Protocol': 'h2', 'method': str(header[METHOD]),\
                                                        'url': url, 'request': now, 'response':0, 'data':[],\
                                                        'push': True}
            elif streamType.int_value == RESET:
                if streamId not in objects[tcpStream]:
                    logging.warning("Unknown HTTP2 stream identifier. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
                    return
                objects[tcpStream][streamId]['reset'] = now
            else:
                # we do not care streams other than data or header
                pass
    return


def autopsy_http_header_ssl(header, packet, objects, tcpQueue, tcpTimestamps):
    p = packet # for short

    tcpStream = int(p.tcp.stream)
    now = float(p.sniff_timestamp)

    method = ''
    status = 0
    target = ''

    #check format and type
    httpType = header[0].lower().find('HTTP/1.1'.lower())
    if httpType == -1:
        # something is wrong. No http/1.1 found
        logging.warning("Wrong http version, packet#%d", p.number.int_value)
        return
    line =  header[0].split(' ', 2) # beware: 204 No content
    if len(line) < 3:
        # bad header format
        logging.warning("wrong header format %s packet#%d", line, p.number.int_value)
        return

    if httpType == 0:
        # the first line is a status line
        status = int(line[1])
    else:
        # the first line is a request line
        method = line[0]
        target = line[1]
    #the optional headers
    headers = Message(StringIO(header[1]))

    if method:
        # request
        url = 'https://' + headers['Host'] + target
        if tcpStream not in objects:
            objects[tcpStream] = {}

        # maintain our fake streamId
        if tcpStream not in tcpQueue:
            tcpQueue[tcpStream] = {'receiving': None, 'queue': [], 'nextUnusedStreamId': 0,}

        streamId = tcpQueue[tcpStream]['nextUnusedStreamId']
        tcpQueue[tcpStream]['nextUnusedStreamId'] += 1
        tcpQueue[tcpStream]['queue'].append(streamId)
        # insert an entry of the object
        objects[tcpStream][streamId] = {'Protocol': 'HTTP/1.1, SSL', 'method': method,\
                                        'url': url, 'request': now, 'response':0, 'data':[]}
    elif status:
        # response
        if tcpStream not in tcpQueue:
            logging.warning("Unknown TCP stream. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
            return
        # start receiving
        if not tcpQueue[tcpStream]['queue']:
            logging.warning("No fate streamId. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
            return
        streamId = tcpQueue[tcpStream]['queue'].pop(0)
        tcpQueue[tcpStream]['receiving'] = streamId
        if streamId not in objects[tcpStream]:
            logging.warning("Unknown fake streamId. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
            return
        objects[tcpStream][streamId]['status'] = status

        # then try to track the tcp packets:
        first = track_down_tcp_segemnts(p, objects, streamId, tcpTimestamps)
        objects[tcpStream][streamId]['response'] = first

    else:
        # nothing
        pass

    return

def autopsy_http_body_ssl(_, packet, objects, tcpQueue, tcpTimestamps):
    # TODO: we might need to check body length to see if the body is received compeletly
    p = packet # for short

    tcpStream = int(p.tcp.stream)

    if (tcpStream not in tcpQueue) or (tcpStream not in objects):
        # this packet could be just other traffic over SSL if no header appeared before
        logging.warning("Unknown App data, packet %d", p.number.int_value)
        return

    currentStreamId = tcpQueue[tcpStream]['receiving']
    if currentStreamId is None:
        logging.warning("HTTP body appears without a header. Packet#%d", p.number.int_value)
        return
    if currentStreamId not in objects[tcpStream]:
        logging.warning("Unknown fake streamId. Packet#%d", p.number.int_value)
        return
    track_down_tcp_segemnts(p, objects, currentStreamId, tcpTimestamps)




def autopsy_http_ssl(packet, objects, tcpQueue, tcpTimestamps):
    p = packet # for short

    if 'tcp' not in p:
        logging.warning("SSL should be over TCP. Packet#%d", p.number.int_value)
        return

    if not 'segment_data' in p.ssl.field_names:
        # this is an SSL control packet
        return

    # decode the payload from "XX:XX:XX" to string
    payload = p.ssl.segment_data.replace(':', '').decode('hex')

    # try to find the header
    boundary = payload.find('\r\n\r\n')
    header = []
    data = ''
    if boundary == -1:
        # this is data
        data = payload
    else:
        # this is header + possible data
        # header[0]: first line, headers[1] optional header lines
        header = payload[:boundary].split('\r\n', 1)
        data = payload[boundary+len('\r\n\r\n'):]
    called_tcp_track = False

    if header:
        # we have a header
        autopsy_http_header_ssl(header, packet, objects, tcpQueue, tcpTimestamps)
        called_tcp_track = True

    if data:
        # there is a data chunk
        if not called_tcp_track:
            # we don't track the body if the body share the same upper layer packet with header
            # as we track the header already
            autopsy_http_body_ssl(data, packet, objects, tcpQueue, tcpTimestamps)

    return

def track_down_tcp_segemnts(packet, objects, streamId, tcpTimestamps):
    # this function tracks down the tcp packets that assemble 'packet' and puts them in 'data' timing field
    # it returns the tcpTimestamp of the first tcp packets in case the caller want to mark it as the response start time
    # NOTE: this function just put 'now' into 'data' if the upper layer is not reassembled
    p = packet # for short

    now = float(p.sniff_timestamp)
    first = now
    tcpStream = int(p.tcp.stream)

    # 'data' layer tells how tcp packets are reassembled
    # example: '4 Reassembled TCP Segments (16690 bytes): #1072(9664), #1074(2416), #1103(2416), #1107(2194)'
    if not ('data' in p and 'tcp_segments' in p.data.field_names):
        # the upper layer is not reassembled, just a single TCP packet
        objects[tcpStream][streamId]['data'].append(now)
        return first # i.e. now

    # XXX: tshark truncates this string if it has more than 240 chars, I compiled tshark to make it 2400.
    segments_str = str(p.data.tcp_segments).split(':')
    if len(segments_str) == 2:
        #a legal string
        segments = segments_str[1].strip().split(',')
        segNumbers = []
        for seg in segments:
            seg = seg.strip().replace('#','').replace(')','').split('(')
            if len(seg) > 0:
                # the first value is the packet number
                if not seg[0]:
                    logging.warning('bad segment string format: %s', p.data.tcp_segments)
                    if len(str(p.data.tcp_segments)) == 239:
                        logging.warning('Detect truncated wireshark label. Need to re-compile tshark to fix this')
                    continue
                segNumbers.append(int(seg[0]))
            else:
                #bad format
                pass
        if tcpStream not in tcpTimestamps:
            logging.warning("No tcp stream recorded for tcp segment timing.\
                Maybe dump is incomplete. tcpStream%d, packet#%d", tcpStream, p.number.int_value)
            return
        # timing for the last packet (this packet) is not recorded, we do it now in case it is needed in the future
        if segNumbers:
            # if not empty, record the first
            # NOTE: we don't know if [0] is the earliest packet, but it looks so
            if segNumbers[0] not in tcpTimestamps[tcpStream]:
                logging.warning("No tcp segment timing recorded. Maybe dump is incomplete. Packet#%d", segNumbers[0])
                return
            first = tcpTimestamps[tcpStream][segNumbers[0]]
        tcpTimestamps[tcpStream][p.number.int_value] = now
        for segNumber in segNumbers:
            if segNumber not in tcpTimestamps[tcpStream]:
                logging.warning("No tcp segment timing recorded. Maybe dump is incomplete. Packet#%d", segNumber)
                continue
            segTime = tcpTimestamps[tcpStream][segNumber]
            # NOTE: timestamps in 'data' could be out of order, it is OK for now
            if segTime not in objects[tcpStream][streamId]['data']:
                # multiple pieces of a upper layer could call this fucntion for the same packet
                # We should avoid the duplication
                # NOTE: lookup a item in a list is HEAVY
                objects[tcpStream][streamId]['data'].append(segTime)
    else:
        #bad format
        pass

    return first

def autopsy_http(packet, objects, tcpQueue, tcpTimestamps):
    p = packet # for short
    if 'tcp' not in p:
        #sometimes there are TCP over udp
        return
    tcpStream = int(p.tcp.stream)
    now = float(p.sniff_timestamp)
    if 'tcp' not in p:
        logging.warning("HTTP should be over TCP. Packet#%d", p.number.int_value)
        return

    if 'request_method' in p.http.field_names:
        # this is a request
        url = str(p.http.request_full_uri)

        if tcpStream not in objects:
            objects[tcpStream] = {}

        # maintain our fake streamId
        if tcpStream not in tcpQueue:
            tcpQueue[tcpStream] = {'receiving': None, 'queue': [], 'nextUnusedStreamId': 0,}

        streamId = tcpQueue[tcpStream]['nextUnusedStreamId']
        tcpQueue[tcpStream]['nextUnusedStreamId'] += 1
        tcpQueue[tcpStream]['queue'].append(streamId)
        if tcpQueue[tcpStream]['receiving'] is None:
            # IMPORTANT!! unlike h2 and HTTP SSL, we need to track down TCP segments as the response packet is desegmented.
            # So every incoming data packet when the request is sent is a response
            tcpQueue[tcpStream]['receiving'] = tcpQueue[tcpStream]['queue'].pop(0)
        # insert an entry of the object
        objects[tcpStream][streamId] = {'Protocol': str(p.http.request_version), 'method': str(p.http.request_method),\
                                        'url': url, 'request': now, 'response':0, 'data':[]}
    elif 'response_code' in p.http.field_names:
        # this is a desegmented response. It means the response is finished, no more traffic for this object
        if tcpStream not in tcpQueue:
            logging.warning("Unknown TCP stream. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
            return
        # end (!!) receiving
        streamId = tcpQueue[tcpStream]['receiving']
        if tcpQueue[tcpStream]['queue']:
            # not empty, should want for next object
            tcpQueue[tcpStream]['receiving'] = tcpQueue[tcpStream]['queue'].pop(0)
        else:
            # or idle
            tcpQueue[tcpStream]['receiving'] = None
        if streamId not in objects[tcpStream]:
            logging.warning("Unknown fake streamId. Maybe tcpdump is incomplete. Packet#%d", p.number.int_value)
            return
        #response timestamp should be the first data packet
        #objects[tcpStream][streamId]['response'] = now
        objects[tcpStream][streamId]['status'] = int(p.http.response_code)

        # then we track down all the tcp packets that assembled this response
        # NOTE: in this script we sometimes treat response header as a piece of data, but sometimes not
        first = track_down_tcp_segemnts(p, objects, streamId, tcpTimestamps)
        objects[tcpStream][streamId]['response'] = first


    return

def autopsy_http_tcp(packet, objects, _, tcpTimestamps):
    p = packet # for short

    if 'segment_data' not in p.tcp.field_names:
        # there is no data, maybe just a control packet
        return

    tcpStream = int(p.tcp.stream)

    if tcpStream not in objects:
        #We only track the tcp data packets after a request on that tcpStream is sent
        return

    now = float(p.sniff_timestamp)

    if tcpStream not in tcpTimestamps:
        #init
        tcpTimestamps[tcpStream] = {}


    if p.tcp.port.int_value == 80:
        # HACK: it's none-SSL and it's from web server to browser
        tcpTimestamps[tcpStream][p.number.int_value] = now
    elif p.tcp.port.int_value == 443:
        # HACK: it's HTTP over SSL or HTTP2. But we don't put tcp for HTTP2 in tcpQueue, so it's HTTP/1.1 + SSL
        tcpTimestamps[tcpStream][p.number.int_value] = now
    else:
        # other TCP
        pass

    return

def retrive_timing(dump):
    objects = {}
    # for none-HTTP2 traffic we need to keep trace of which TCP stream is serving which object on the fly
    # we create/track our fake streamId in the following {tcpStream: {receiving, queue, nextUnusedStreamId} }:
    tcpQueue = {}
    # To trace back the time stamps for previous data packets within one pass, we record timing info
    # {tcpStream:{packetNumber:timestamp}}
    tcpTimestamps = {}

    for p in dump: # for all packets
        if 'http2' in p:
            # this is HTTP2
            autopsy_http2(p, objects, tcpTimestamps)
            #pass
        elif 'http' in p:
            # HTTP
            autopsy_http(p, objects, tcpQueue, tcpTimestamps)
        elif 'ssl' in p:
            # we assume it is HTTP over SSL
            # wireshark has trouble decoding HTTP over SSL
            # we have to do it ourselves
            autopsy_http_ssl(p, objects, tcpQueue, tcpTimestamps)
            #pass
        else:
            pass
        if 'tcp' in p:
            # We do care some TCP packets
            if 'stream' in p.tcp.field_names:
                # If the packet is for http or http over SSL
                autopsy_http_tcp(p, objects, tcpQueue, tcpTimestamps)
        else:
            # other protocols
            pass

    return objects

def create_relative_timestamp(objects):
    # this function change all timestamps except startTime to relative time shifts from startTime in ms
    obj = copy.deepcopy(objects)
    for tcp in obj:
        for stream in obj[tcp]:
            start = float(obj[tcp][stream]['request'])
            response = float(obj[tcp][stream]['response'])
            reset = float(obj[tcp][stream].get('reset', 0))
            if response == 0: # for the ones with on response
                logging.warning('Object %s via %s has no response found', obj[tcp][stream]['url'],obj[tcp][stream]['Protocol'] )
                response = start
            assert response >= start,\
                "response comes earlier than request, %s, %f < %f "%(obj[tcp][stream]['url'], response, start)
            obj[tcp][stream]['response'] = (response - start)*1000
            if reset:
                obj[tcp][stream]['reset'] = (reset - start)*1000
            data = obj[tcp][stream]['data']
            for i in range(len(data)):
                dataStamp = float(data[i])
                assert dataStamp >= start,\
                    "data comes earlier than request, %s, %f < %f"%(obj[tcp][stream]['url'], dataStamp, start)
                data[i] = (dataStamp - start)*1000
            obj[tcp][stream]['data'] = data
    return obj

def sort_by_time(objects):
    # this function returns a sorted list of tuples, [(startTime, timing_data_we_record)]
    obj = {}
    for tcp in objects:
        for stream in objects[tcp]:
            start = float(objects[tcp][stream]['request'])
            while start in obj:
                # timestamp is the same, shift 0.01ms
                start += 1e-5
            obj[start] = objects[tcp][stream]

    return sorted(obj.items())

def group_by_url(objects):
    # this function groups records by their urls {url: timing_data_we_record}
    obj = {}
    for tcp in objects:
        for stream in objects[tcp]:
            url = objects[tcp][stream]['url']
            if url not in obj:
                obj[url] = []
            obj[url].append(objects[tcp][stream])

    return obj


def example():
    cap = pyshark.FileCapture('/Users/ywu/cwpf_test/cmu_http.pcap',\
                              sslkey_path='/Users/ywu/cwpf_test/ssl_keylog',\
                              http_only=True, tshark_path='/Users/ywu/cwpf_test/wireshark-1.99.7/build/run/tshark')
    objs = retrive_timing(cap)
    r_obj = create_relative_timestamp(objs)
    s_obj = group_by_url(r_obj)
    print json.dumps(s_obj, indent=4)

def execute(args):
    paras = []
    if args.heuristic:
        paras += ['-o', 'http2.heuristic_http2:TRUE']
    else:
        paras += ['-o', 'http2.heuristic_http2:FALSE']

    logging.info('Start analyzing tcp dump file')
    cap = pyshark.FileCapture(args.dumpfile, sslkey_path=args.key, http_only=(not args.all),
                              tshark_path=args.bin, other_paras=paras)
    objs = retrive_timing(cap)
    logging.info('Start computing relative timestamp')
    relative_obj = create_relative_timestamp(objs)
    if args.sort:
        logging.info('Start sorting records')
        final_obj = sort_by_time(relative_obj)
    else:
        logging.info('Start grouping records')
        final_obj = group_by_url(relative_obj)
    if args.output:
        with open(args.output, 'w') as outfile:
            json.dump(final_obj, outfile, indent = 4)
    else:
        print json.dumps(final_obj, indent=4)

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='HTTP(2) traffic analyzer for tcpdump file.')
    parser.add_argument('dumpfile', help='The .pcap file generated by tcpdump')
    parser.add_argument('-k', '--key', default=None, help='The ssl key file the browser dumped')
    parser.add_argument('-a', '--all', action='store_true', default=False, help='Also work on traffic other than TCP over port 80 or port 443')
    parser.add_argument('-b', '--bin', default=None, help='Path to the tshark binary')
    parser.add_argument('-o', '--output', default=None, help='Output file path instead of STDOUT')
    parser.add_argument('-g', '--heuristic', action='store_true', default=False,\
                                        help='Enable weak HTTP2 heuristic. Google traffic may need it. Beware: false positives')
    parser.add_argument('-s', '--sort', action='store_true', default=False,\
                                        help='Sort output by objects\' timestamp (instead of group by url)' )
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
