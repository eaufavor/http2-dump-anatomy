#!/usr/bin/env python
import pyshark, copy
from mimetools import Message
from StringIO import StringIO

#HTTP2 stream types
HEADER_TYPE = 1
DATA_TYPE = 0

#HTTP2 header types
METHOD = ':method'
STATUS = ':status'

def autopsy_http2(packet, objects):
    p = packet # for short

    assert 'tcp' in p, "HTTP2 should be over TCP. Packet#%d"%p.number.int_value
    tcpStream = int(p.tcp.stream)
    now = float(p.sniff_timestamp)

    if not 'type' in p.http2.field_names:
        # this is the magic packet
        return

    # prepare the container
    if tcpStream not in objects:
        objects[tcpStream] = {}

    for streamType in p.http2.get_field('type').all_fields:
        #local stream index in this packet
        streamIndex = p.http2.get_field('type').all_fields.index(streamType)
        #HTTP2 stream id
        streamId = p.http2.get_field('streamid').all_fields[streamIndex].int_value
        # find if HEADER or DATA is here
        if streamType.int_value == HEADER_TYPE:
            # build the header dict
            header = {}
            for fi in range(len(p.http2.get_field('header').all_fields)):
                key = p.http2.get_field('header_name').all_fields[fi].showname_value.strip().lower()
                value = p.http2.get_field('header_value').all_fields[fi].showname_value.strip()
                header[key] = value
            if METHOD in header:
                # the header is a request header
                # Note: query string is included in :path?
                url = header[':scheme'] + '://' + header[':authority'] + header[':path']
                # each object should have its own streamId
                assert not streamId in objects[tcpStream],\
                    "HTTP2 stream identifiers cannot be reused. Packet#%d"%p.number.int_value
                # insert a new object entry
                objects[tcpStream][streamId] = {'Protocol': 'h2', 'method': str(header[METHOD]),\
                                                'url': url, 'request': now, 'response':0, 'data':[]}
            elif STATUS in header:
                # this is a response header
                assert streamId in objects[tcpStream],\
                    "Unknown HTTP2 stream identifier. Maybe tcpdump is incomplete. Packet#%d"%p.number.int_value
                objects[tcpStream][streamId]['response'] = now
                objects[tcpStream][streamId]['status'] = int(header[STATUS])
            else:
                print "Unknown header", p.http2
        elif streamType.int_value == DATA_TYPE:
            # this is a DATA stream
            assert streamId in objects[tcpStream],\
                "Unknown HTTP2 stream identifier. Maybe tcpdump is incomplete. Packet#%d"%p.number.int_value
            objects[tcpStream][streamId]['data'].append(now)
        else:
            # we do not care streams other than data or header
            pass
    return


def autopsy_http_header_ssl(header, packet, objects, tcpQueue):
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
        print "wrong http version, packet#%d"%p.number.int_value
        return
    line =  header[0].split(' ', 2) # beware: 204 No content
    if len(line) < 3:
        # bad header format
        print "wrong header format", line, "packet#%d"%p.number.int_value
        return

    if httpType == 0:
        # the first line is a status line
        #print "status line", header[0]
        status = int(line[1])
    else:
        # the first line is a request line
        method = line[0]
        target = line[1]
        #print "request line", header[0]
        #print "header line", header[1]
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
        assert tcpStream in tcpQueue,\
            "Unknown TCP stream. Maybe tcpdump is incomplete. Packet#%d"%p.number.int_value
        # start receiving
        streamId = tcpQueue[tcpStream]['queue'].pop(0)
        tcpQueue[tcpStream]['receiving'] = streamId
        assert streamId in objects[tcpStream],\
            "Unknown fake streamId. Maybe tcpdump is incomplete. Packet#%d"%p.number.int_value
        objects[tcpStream][streamId]['response'] = now
        objects[tcpStream][streamId]['status'] = status
    else:
        # nothing
        pass

    return

def autopsy_http_body_ssl(body, packet, objects, tcpQueue):
    # TODO: we might need to check body length to see if the body is received compeletly
    p = packet # for short

    tcpStream = int(p.tcp.stream)
    now = float(p.sniff_timestamp)

    if (tcpStream not in tcpQueue) or (tcpStream not in objects):
        # this packet could be just other traffic over SSL if no header appeared
        print "Unknown App data", p.number
        return

    currentStreamId = tcpQueue[tcpStream]['receiving']
    assert not currentStreamId == None, "HTTP body appears without a header. Packet#%d"%p.number.int_value
    assert currentStreamId in objects[tcpStream], "Unknown fake streamId. Packet#%d"%p.number.int_value
    objects[tcpStream][currentStreamId]['data'].append(now)




def autopsy_http_ssl(packet, objects, tcpQueue):
    p = packet # for short

    assert 'tcp' in p, "SSL should be over TCP. Packet#%d"%p.number.int_value

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
    #print 'header', header
    #print 'data', data[:20]

    if header:
        # we have a header
        autopsy_http_header_ssl(header, packet, objects, tcpQueue)

    if data:
        # there is a data chunk
        autopsy_http_body_ssl(data, packet, objects, tcpQueue)

    return

def autopsy_http(packet, objects, tcpQueue, tcpTimestamps):
    p = packet # for short
    if 'tcp' not in p:
        #sometimes there are TCP over udp
        return
    tcpStream = int(p.tcp.stream)
    now = float(p.sniff_timestamp)
    assert 'tcp' in p, "HTTP should be over TCP. Packet#%d"%p.number.int_value

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
        assert tcpStream in tcpQueue,\
            "Unknown TCP stream. Maybe tcpdump is incomplete. Packet#%d"%p.number.int_value
        # end (!!) receiving
        streamId = tcpQueue[tcpStream]['receiving']
        if tcpQueue[tcpStream]['queue']:
            # not empty, should want for next object
            tcpQueue[tcpStream]['receiving'] = tcpQueue[tcpStream]['queue'].pop(0)
        else:
            # or idle
            tcpQueue[tcpStream]['receiving'] = None
        assert streamId in objects[tcpStream],\
            "Unknown fake streamId. Maybe tcpdump is incomplete. Packet#%d"%p.number.int_value
        #response timestamp should be the first data packet
        #objects[tcpStream][streamId]['response'] = now
        objects[tcpStream][streamId]['status'] = int(p.http.response_code)
        if 'data' in p and 'tcp_segments' in p.data.field_names:
            # 'data' layer tells how tcp packets are reassembled
            # example: '4 Reassembled TCP Segments (16690 bytes): #1072(9664), #1074(2416), #1103(2416), #1107(2194)'
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
                            print p.data.tcp_segments
                        segNumbers.append(int(seg[0]))
                    else:
                        #bad format
                        pass
                assert tcpStream in tcpTimestamps,\
                    "No tcp stream recorded for tcp segment timing. Maybe dump is incomplete. tcpStream%d"%tcpStream
                # timing for the last packet (this packet) is not recorded, we do it now in case it is needed in the future
                if segNumbers:
                    # if not empty, first must be response header
                    assert segNumbers[0] in tcpTimestamps[tcpStream],\
                        "No tcp segment timing recorded. Maybe dump is incomplete. Packet%d"%segNumbers[0]
                    segTime = tcpTimestamps[tcpStream][segNumbers[0]]
                    objects[tcpStream][streamId]['response'] = segTime
                tcpTimestamps[tcpStream][p.number.int_value] = now
                for segNumber in segNumbers:
                    assert segNumber in tcpTimestamps[tcpStream],\
                        "No tcp segment timing recorded. Maybe dump is incomplete. Packet%d"%segNumber
                    segTime = tcpTimestamps[tcpStream][segNumber]
                    objects[tcpStream][streamId]['data'].append(segTime)
            else:
                #bad format
                pass
        else:
            # This could be the only reply
            objects[tcpStream][streamId]['data'].append(now)


    return

def autopsy_http_tcp(packet, objects, tcpQueue, tcpTimestamps):
    p = packet # for short

    tcpStream = int(p.tcp.stream)
    now = float(p.sniff_timestamp)

    if tcpStream not in tcpQueue:
        #already tested when calling this function but just in case
        return
    if tcpStream not in objects:
        return

    if 'segment_data' not in p.tcp.field_names:
        # there is no data, maybe a ACK packet
        return
    #streamId = tcpQueue[tcpStream]['receiving']

    if tcpStream not in tcpTimestamps:
        #init
        tcpTimestamps[tcpStream] = {}


    if p.tcp.port.int_value == 80:
        # HACK: it's none-SSL and it's from web server to browser
        tcpTimestamps[tcpStream][p.number.int_value] = now
        """
        if streamId is None:
            # no one expects data
            # It could be push packet but not likely via port 80
            return
        if not objects[tcpStream][streamId]['data']:
            # empty list, we assume the first response packet contains response header
            # NOTE: by doing this we make HTTP (looks) more responsive than HTTPS
            #objects[tcpStream][streamId]['response'] = now
            pass
        """
        #objects[tcpStream][streamId]['data'].append(now)
    elif p.tcp.port.int_value == 443:
        # HACK: it's HTTP over SSL or HTTP2. But we don't put tcp for HTTP2 in tcpQueue, so it's HTTP/1.1 + SSL
        # TODO: track these data packets
        pass

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
            autopsy_http2(p, objects)
            #pass
        elif 'http' in p:
            # HTTP
            autopsy_http(p, objects, tcpQueue, tcpTimestamps)
        elif 'ssl' in p:
            # we assume it is HTTP over SSL
            # wireshark has trouble decoding HTTP over SSL
            # we have to do it ourselves
            autopsy_http_ssl(p, objects, tcpQueue)
            #pass
        elif 'tcp' in p:
            # We do care some TCP packets
            if 'stream' in p.tcp.field_names and int(p.tcp.stream) in tcpQueue:
                # If the packet is for http or http over SSL
                autopsy_http_tcp(p, objects, tcpQueue, tcpTimestamps)
        else:
            # other protocols
            continue

    return objects

def create_relative_timestamp(objects):
    # this function change all timestamps except startTime to relative time shifts from startTime in ms
    obj = copy.deepcopy(objects)
    for tcp in obj:
        for stream in obj[tcp]:
            start = float(obj[tcp][stream]['request'])
            response = float(obj[tcp][stream]['response'])
            if response == 0: # for the ones with on response
                response = start
            assert response >= start,\
                "response comes earlier than request, %s, %f < %f "%(obj[tcp][stream]['url'], response, start)
            obj[tcp][stream]['response'] = (response - start)*1000
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


def main():
    cap = pyshark.FileCapture('/Users/ywu/cwpf_test/cmu5.pcap',\
                              sslkey_path='/Users/ywu/cwpf_test/ssl_keylog',\
                              http_only=True, tshark_path='/Users/ywu/cwpf_test/wireshark-1.99.7/build/run/tshark')
    objs = retrive_timing(cap)
    #print objs
    r_obj = create_relative_timestamp(objs)
    s_obj = sort_by_time(r_obj)
    for item in s_obj:
        print item

if __name__ == '__main__':
    main()
