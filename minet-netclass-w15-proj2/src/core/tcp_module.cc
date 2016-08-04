#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <list>
#include <time.h>

#include <iostream>

#include "Minet.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;

unsigned int DEFAULT_TIMERTRIES = 5;
double TIMEOUT_INTERVAL = 10.0; //seconds

Time getNewExpireTime() {
  Time current;
  current.SetToCurrentTime();
  current.tv_sec += TIMEOUT_INTERVAL;
  return current;
}

void resetTimeOut(ConnectionToStateMapping<TCPState>* m) {
  m->timeout = getNewExpireTime();
  m->bTmrActive = true;
}

IPHeader createIPHeader(Connection c, int dataLen) {
  IPHeader ih;
  ih.SetSourceIP(c.src);
  ih.SetDestIP(c.dest);
  ih.SetProtocol(IP_PROTO_TCP);
  ih.SetTotalLength(dataLen + IP_HEADER_BASE_LENGTH);
  return ih;
}

TCPHeader createTCPHeader(Connection c, TCPState ts, unsigned char flags, Packet &p) {
  TCPHeader th;
  th.SetSourcePort(c.srcport, p);
  th.SetDestPort(c.destport, p);
  th.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, p);
  th.SetSeqNum(ts.last_sent, p);
  th.SetAckNum(ts.last_recvd, p);
  th.SetWinSize((unsigned short)ts.N, p);
  th.SetFlags(flags, p);
  th.SetUrgentPtr(0, p);
  th.SetChecksum(0);
  th.RecomputeChecksum(p);
  return th;
}

Packet createPacket(ConnectionToStateMapping<TCPState>* m, unsigned char flags, Buffer data) {
  Packet p;
  if (data.GetSize() > 0) {
    p = *(new Packet(data));
  }
  IPHeader iph = createIPHeader(m->connection, TCP_HEADER_BASE_LENGTH + data.GetSize());
  p.PushFrontHeader(iph);
  TCPHeader tcph = createTCPHeader(m->connection, m->state, flags, p);
  p.PushBackHeader(tcph);
  cerr << "New Packet created " << p << " and ";
  cerr << "TCP Packet: IP Header is "<<iph<<" and ";
  cerr << "TCP Header is "<<tcph << " and ";
  cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID") << endl;
  return p;
}

Connection createConnectionFromPacketHeaders(IPHeader iph, TCPHeader tcph) {
  IPAddress sourceIP;
  IPAddress destIP;
  unsigned char protocol;
  unsigned short sourcePort;
  unsigned short destPort;

  iph.GetDestIP(sourceIP);
  iph.GetSourceIP(destIP);
  iph.GetProtocol(protocol);
  tcph.GetDestPort(sourcePort);
  tcph.GetSourcePort(destPort);

  return Connection(sourceIP, destIP, sourcePort, destPort, protocol);
}

ConnectionToStateMapping<TCPState>* findConnectionToStateMapping(
    ConnectionList<TCPState> &clist, Connection c) {
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
  if (cs == clist.end()) {
    return NULL;
  }
  return &(*cs);
}

bool addNewConnectionToStateMapping(
    ConnectionList<TCPState> &clist, Connection c, TCPState* ts) {
  if (ts == NULL) {
    ts = new TCPState((unsigned int)rand(), CLOSED, DEFAULT_TIMERTRIES);
  }
  ConnectionToStateMapping<TCPState>* m = new ConnectionToStateMapping<TCPState>(c, Time(), *ts, false);
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
  if (cs!=clist.end()) {
    cerr << "Port has been used!";
    return false;
  }
  clist.push_back((*m));
  return true;
}

void eraseConnectionToStateMapping(ConnectionList<TCPState> &clist, Connection c) {
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
  if (cs != clist.end()) {
    clist.erase(cs);
  }
}

unsigned queueData(TCPState &ts, Buffer data) {
  size_t newDataSize = data.GetSize();
  size_t usedDataSize = ts.SendBuffer.GetSize();
  size_t avaliableDataSize = (size_t)ts.TCP_BUFFER_SIZE - usedDataSize;
  if (newDataSize <= avaliableDataSize) {
    ts.SendBuffer.AddBack(data);
    return static_cast<unsigned>(newDataSize);
  }
  ts.SendBuffer.AddBack(data.Extract(0, avaliableDataSize));
  return static_cast<unsigned>(avaliableDataSize);
}

unsigned sendNewPacket(ConnectionToStateMapping<TCPState>* m, MinetHandle mux) {
  //cerr << "sendNewPacket" << endl;
  //cerr << m->state.last_sent << endl;
  //cerr << m->state.last_acked << endl;
  unsigned offsetlastsent;
  TCPState s = m->state;
  if(s.last_acked < s.last_sent) {
    offsetlastsent = s.last_sent - s.last_acked;
  } else {
    offsetlastsent = SEQ_LENGTH_MASK - s.last_acked + s.last_sent + 1;
  }

  size_t bytesize = MIN_MACRO(s.N - offsetlastsent, s.SendBuffer.GetSize() - offsetlastsent);
  bytesize = MIN_MACRO(bytesize, TCP_MAXIMUM_SEGMENT_SIZE);

  if (bytesize > 0) {
    //cerr << s.SendBuffer.GetSize() << endl;
    //cerr << bytesize << endl;
    //cerr << offsetlastsent << endl;
    char* data = new char[bytesize+1];
    s.SendBuffer.GetData(data, bytesize, offsetlastsent);
    
    MinetSend(mux, createPacket(m, (unsigned char)16, Buffer(data, bytesize))); //Send ACK and Data
    m->state.SetLastSent(s.last_sent + bytesize);
  }


  //cerr << m->state.last_sent << endl;
  //cerr << m->state.last_acked << endl;
  return static_cast<unsigned>(bytesize);
}

unsigned sendData(ConnectionToStateMapping<TCPState>* m, MinetHandle mux) {
  unsigned sum = 0;
  unsigned count = 0;
  while ((count = sendNewPacket(m, mux)) != 0) {
    sum += count;
  }
  return sum;
}

void processPacketFromBelow(Packet p, ConnectionList<TCPState> &clist,
    MinetHandle mux, MinetHandle sock) {
  unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
  cerr << "estimated header len="<<tcphlen<<"\n";
  p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
  IPHeader iph=p.FindHeader(Headers::IPHeader);
  TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

  unsigned short ipTotalLen;
  unsigned char ipHeaderLen;
  iph.GetTotalLength(ipTotalLen);
  iph.GetHeaderLength(ipHeaderLen);
  unsigned dataLen = ipTotalLen - ipHeaderLen * 4 - tcphlen;
  Buffer payload;
  if (dataLen > 0) {
    char* temp = new char[dataLen];
    p.GetPayload().GetData(temp, dataLen, 0);
    payload = *(new Buffer(temp, dataLen));
  }

  cerr << "TCP Packet: IP Header is "<<iph<<" and ";
  cerr << "TCP Header is "<<tcph << " and ";
  cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID") << endl;

  Connection c = createConnectionFromPacketHeaders(iph, tcph);

  unsigned char flags;
  tcph.GetFlags(flags);
  bool isACK = IS_ACK(flags);
  bool isSYN = IS_SYN(flags);
  bool isFIN = IS_FIN(flags);;
  bool isRST = IS_RST(flags);;
  unsigned int seqNum;
  unsigned int ackNum;
  tcph.GetSeqNum(seqNum);
  tcph.GetAckNum(ackNum);

  ConnectionToStateMapping<TCPState>* m = findConnectionToStateMapping(clist, c);
  if (m != NULL) {
    cerr << "Connection To State Mapping Found: " << *m << endl;
    switch (m->state.GetState()) {
    case LISTEN: {
      cerr << "State is LISTEN" << endl;
      if (isSYN) {
        cerr << "Got SYN, sending SYN ACK" << endl;
        m->connection = c;
        m->state.SetLastRecvd(seqNum + 1);
        Packet p = createPacket(m, (unsigned char)18, Buffer()); //Send SYN ACK
        MinetSend(mux, p); 
        m->state.SetLastSent(m->state.last_sent + 1);
        m->state.SetState(SYN_RCVD);
        resetTimeOut(m);
        MinetSend(sock, SockRequestResponse(WRITE, c, Buffer(), 0, EOK));
      } else {
        cerr << "Sending RST ACK" << endl;
        TCPState ts((unsigned int)rand(), CLOSED, DEFAULT_TIMERTRIES);
        ConnectionToStateMapping<TCPState>* map = new ConnectionToStateMapping<TCPState>(c, Time(), ts, false);
        map->state.SetLastRecvd(seqNum + 1);
        Packet p = createPacket(map, (unsigned char)20, Buffer()); //Send RST ACK
        MinetSend(mux, p); 
      }
    }
    break;
    case SYN_SENT: {
      cerr << "State is SYN_SENT" << endl;
      if (isRST) {
        m->state.SetLastSent(m->state.last_sent - 1);
        Packet p = createPacket(m, (unsigned char)2, Buffer());  //Resend SYN
        m->state.SetLastSent(m->state.last_sent + 1);
        MinetSend(mux, p);
        resetTimeOut(m);
      } else {
        if (isACK && ackNum == m->state.last_sent) {
          cerr << "Got ACK" << endl;
          m->state.last_acked = ackNum;
          m->state.SetState(SYN_SENT1);
          m->bTmrActive = false;
        }

        if (isSYN) {
          cerr << "Got SYN, sending ACK" << endl;
          m->state.SetLastRecvd(seqNum + 1);
          MinetSend(mux, createPacket(m, (unsigned char)16, Buffer())); //Send ACK
          m->state.SetState(ESTABLISHED);
          resetTimeOut(m);
          MinetSend(sock, SockRequestResponse(WRITE, c, Buffer(), 0, EOK));
        }
      }
    }
    break;
    case SYN_SENT1: {
      cerr << "State is SYN_SENT1" << endl;
      if (isSYN) {
        cerr << "Got SYN, sending ACK" << endl;
        m->state.SetLastRecvd(seqNum + 1);
        MinetSend(mux, createPacket(m, (unsigned char)16, Buffer())); //Send ACK
        m->state.SetState(ESTABLISHED);
        resetTimeOut(m);
        MinetSend(sock, SockRequestResponse(WRITE, c, Buffer(), 0, EOK));
      }
    }
    break;
    case SYN_RCVD: {
      cerr << "State is SYN_RCVD" << endl;
      if (isRST) {
        Connection halfBoundC(m->connection.src, IPAddress(), m->connection.srcport, 0, m->connection.protocol);
        eraseConnectionToStateMapping(clist, m->connection);
        addNewConnectionToStateMapping(clist, halfBoundC, NULL);
        m = findConnectionToStateMapping(clist, halfBoundC);
        m->state.SetState(LISTEN);
      } else {
        if (isACK && ackNum == m->state.last_sent) {
          cerr << "Got ACK" << endl;
          m->state.last_acked = ackNum;
          m->state.SetState(ESTABLISHED);
          m->bTmrActive = false;
        }

        if (dataLen > 0) {
          cerr << "Got Data, sending to sock_module" << endl;
          MinetSend(sock, SockRequestResponse(WRITE, c, payload, 0, EOK));
        }
      }
    }
    break;
    case ESTABLISHED: {
      cerr << "State is ESTABLISHED" << endl;
      if (isRST) {
        m->state.SetState(CLOSED);
        break;
      }

      if (isACK && m->state.SetLastAcked(ackNum)) {
        cerr << "Got ACK, sending Data" << endl;
        m->state.last_acked = ackNum;
        sendData(m, mux);
        resetTimeOut(m);
      }

      if (isFIN) {
        cerr << "Got FIN, sending FIN ACK" << endl;
        m->state.SetLastRecvd(seqNum + 1);
        MinetSend(mux, createPacket(m, (unsigned char)17, Buffer())); //Send FIN ACK
        m->state.SetLastSent(m->state.last_sent + 1);
        m->state.SetState(LAST_ACK);
        resetTimeOut(m);
      }

      if (dataLen > 0) {
        cerr << "Passing data to sock_module" << endl;
        MinetSend(sock, SockRequestResponse(WRITE, c, payload, 0, EOK));
        if (seqNum != m->state.last_recvd) {
          cerr << "Sending ACK for wrong data" << endl;
          MinetSend(mux, createPacket(m, (unsigned char)16, Buffer())); //Send ACK
        }
      }
    }
    break;
    case SEND_DATA: {} break;
    case FIN_WAIT1: {
      cerr << "State is FIN_WAIT1" << endl;
      if (isFIN) {
        cerr << "Got FIN, sending ACK" << endl;
        m->state.SetLastRecvd(seqNum + 1);
        MinetSend(mux, createPacket(m, (unsigned char)16, Buffer())); //Send ACK
        resetTimeOut(m);
        if (isACK && ackNum == m->state.last_sent) {
          m->state.SetState(TIME_WAIT);
        } else {
          m->state.SetState(CLOSING);
        }
      } else if (isACK && ackNum == m->state.last_sent) {
        cerr << "Got ACK, sending ACK" << endl;
        m->state.SetState(FIN_WAIT2);
        m->bTmrActive = false;
      }
    }
    break;
    case FIN_WAIT2: {
      cerr << "State is FIN_WAIT2" << endl;
      if (isFIN) {
        cerr << "Got FIN, sending ACK" << endl;
        m->state.SetLastRecvd(seqNum + 1);
        MinetSend(mux, createPacket(m, (unsigned char)16, Buffer())); //Send ACK
        resetTimeOut(m);
        m->state.SetState(TIME_WAIT);
      }
    }
    break;
    case CLOSE_WAIT: {} break;
    case CLOSING: {
      cerr << "State is CLOSING" << endl;
      if (isACK && ackNum == m->state.last_sent) {
        cerr << "Got ACK" << endl;
        m->state.SetState(TIME_WAIT);
      }
    }
    break;
    case TIME_WAIT: {
      if (isFIN) {
        cerr << "Got FIN, sending ACK" << endl;
        m->state.SetLastRecvd(seqNum + 1);
        MinetSend(mux, createPacket(m, (unsigned char)16, Buffer())); //Send ACK
        resetTimeOut(m);
      }
    }
    break;
    case LAST_ACK: {
      cerr << "State is LAST_ACK" << endl;
      if (isACK && ackNum == m->state.last_sent) {
        cerr << "Got ACK" << endl;
        m->state.SetState(CLOSED);
      }
    }
    break;
    default: {}
    }
  }
}


void processTimeOutEvent(ConnectionToStateMapping<TCPState>* m, MinetHandle mux, MinetHandle sock) {
  switch (m->state.GetState()) {
  case SYN_RCVD: {
    cerr << "State is SYN_RCVD, resending SYN ACK" << endl;
    Packet p = createPacket(m, (unsigned char)18, Buffer()); //Send SYN ACK
    MinetSend(mux, p); 
    resetTimeOut(m);
  }
  break;
  case SYN_SENT: {
    cerr << "State is SYN_SENT, resending SYN" << endl;
    m->state.SetLastSent(m->state.last_sent - 1);
    Packet p = createPacket(m, (unsigned char)2, Buffer());  //Resend SYN
    m->state.SetLastSent(m->state.last_sent + 1);
    MinetSend(mux, p);
    resetTimeOut(m);
  }
  break;
  case ESTABLISHED: {
    cerr << "State is ESTABLISHED, resending data" << endl;
    m->state.SetLastSent(m->state.last_acked); //Resend data
    sendData(m, mux);
    resetTimeOut(m);
  }
  break;
  case FIN_WAIT1: {
    cerr << "State is FIN_WAIT1, resending FIN" << endl;
    m->state.SetLastSent(m->state.last_sent - 1);
    MinetSend(mux, createPacket(m, (unsigned char)1, Buffer())); //Resend FIN
    m->state.SetLastSent(m->state.last_sent + 1);
    resetTimeOut(m);
  }
  break;
  case LAST_ACK: {
    cerr << "State is LAST_ACK, resending FIN ACK" << endl;
    m->state.SetLastSent(m->state.last_sent - 1);
    MinetSend(mux, createPacket(m, (unsigned char)17, Buffer())); //Resend FIN ACK
    m->state.SetLastSent(m->state.last_sent + 1);
    resetTimeOut(m);
  }
  break;
  case CLOSING: {
    cerr << "State is CLOSING, resending FIN" << endl;
    m->state.SetLastSent(m->state.last_sent - 1);
    MinetSend(mux, createPacket(m, (unsigned char)1, Buffer())); //Resend FIN
    m->state.SetLastSent(m->state.last_sent + 1);
    resetTimeOut(m);
  }
  break;
  case TIME_WAIT: {
    cerr << "State is TIME_WAIT" << endl;
    m->state.SetState(CLOSED);
  }
  break;
  default: {};
  }
}

void processSockRequestResponseFromAbove(SockRequestResponse s, ConnectionList<TCPState> &clist,
    MinetHandle mux, MinetHandle sock) {
  //cerr << "Received Socket Request:" << s << endl;
  switch (s.type) {
  case CONNECT: {
    bool success = addNewConnectionToStateMapping(clist, s.connection, NULL);
    if (!success) {
      cerr << "Failed to create new Connection To State Mapping" << endl;
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, ENOMATCH));
    } else {
      cerr << "Got CONNECT, sending SYN" << endl;
      ConnectionToStateMapping<TCPState>* m = findConnectionToStateMapping(clist, s.connection);
      Packet p = createPacket(m, (unsigned char)2, Buffer());  //Send SYN
      MinetSend(mux, p);
      m->state.SetLastSent(m->state.last_sent + 1);
      m->state.SetState(SYN_SENT);
      resetTimeOut(m);
      //cerr << "New Full Bound Connection To State Mapping Created: " << *m << endl;
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, EOK));
    }
  }
  break;
  case ACCEPT: {
    bool success = addNewConnectionToStateMapping(clist, s.connection, NULL);
    if (!success) {
      cerr << "Failed to create new Connection To State Mapping" << endl;
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, ERESOURCE_UNAVAIL));
    } else {
      cerr << "Got ACCEPT, LISTENNING" << endl;
      ConnectionToStateMapping<TCPState>* m = findConnectionToStateMapping(clist, s.connection);
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, EOK));
      m->state.SetState(LISTEN);
    }
  }
  break;
  case WRITE: {
    ConnectionToStateMapping<TCPState>* m = findConnectionToStateMapping(clist, s.connection);
    if (m == NULL) {
      cerr << "Failed to create new Connection To State Mapping" << endl;
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, ENOMATCH));
    } else if (m->state.stateOfcnx != ESTABLISHED) {
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, EINVALID_OP));
    } else {
      cerr << "Got WRITE, bufferring and sending data" << endl;
      unsigned bytesQueued = queueData(m->state, s.data);
      //cerr << bytesQueued << " bytes data queued" << endl;
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), bytesQueued, EOK));
      sendData(m, mux);
    }
  }
  break;
  case FORWARD: {;} break;
  case CLOSE: {
    ConnectionToStateMapping<TCPState>* m = findConnectionToStateMapping(clist, s.connection);
    if (m == NULL) {
      cerr << "Failed to create new Connection To State Mapping" << endl;
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, ENOMATCH));
    } else {
      cerr << "Got CLOSE, sending FIN" << endl;
      MinetSend(mux, createPacket(m, (unsigned char)1, Buffer())); //Send FIN
      m->state.SetLastSent(m->state.last_sent + 1);
      m->state.SetState(FIN_WAIT1);
      resetTimeOut(m);
      MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, EOK));
    }
  }
  break;
  case STATUS: {
    ConnectionToStateMapping<TCPState>* m = findConnectionToStateMapping(clist, s.connection);
    if (m != NULL && s.bytes > 0) {
      cerr << "Got STATUS, sending ACK" << endl;
      m->state.SetLastRecvd(m->state.last_recvd + s.bytes);
      MinetSend(mux, createPacket(m, (unsigned char)16, s.data)); //Send ACK
    }
  }
  break;
  default: {}
  }
}

bool isDead(ConnectionToStateMapping<TCPState> m) {
  return m.state.GetState() == CLOSED || (m.state.ExpireTimerTries() && m.bTmrActive);
}

bool isTimeOut(ConnectionToStateMapping<TCPState> m, Time current) {
  return m.bTmrActive && m.timeout < current;
}

int main(int argc, char *argv[]) {
  MinetHandle mux, sock;
  ConnectionList<TCPState> clist;

  MinetInit(MINET_TCP_MODULE);
  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;
  double timeout = 2;
  while (MinetGetNextEvent(event, timeout)==0) {
    Time current;
    current.SetToCurrentTime();
    std::list<Connection> deadConnections;
    for (ConnectionList<TCPState>::iterator cs = clist.begin();
        cs != clist.end(); cs++) {
      if (isDead(*cs)) {
        deadConnections.push_back((*cs).connection);
      } else if (isTimeOut(*cs, current)) {
        cerr << "Timeout Connection: " << cs->connection << endl;
        processTimeOutEvent(&(*cs), mux, sock);
      }
    }

    //remove dead connections
    for (std::list<Connection>::iterator i = deadConnections.begin();
        i != deadConnections.end(); i++) {
      eraseConnectionToStateMapping(clist, (*i));
    }

    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      cerr << "butts butts butts" << endl;
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        Packet p;
        MinetReceive(mux,p);
        processPacketFromBelow(p, clist, mux, sock);
      }

      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        processSockRequestResponseFromAbove(s, clist, mux, sock);
      }
    }
  }
  return 0;
}

