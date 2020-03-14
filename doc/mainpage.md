
@mainpage UPF source documentation

@section Overview

This is a kit of C++ libraries to build programs (and other
libraries) handling packets of networking traffic.

The main library is NetworkLib, providing core types and
functionalities. Other libraries depend on it.

While most code actually resides in header files (to allow inlining
and better optimizations), these are not header-only libraries: as
such they have to be compiled first, and then linked against your
executable.

@subsection NetworkLib NetworkLib overview

NetworkLib provides the basic building blocks to deal with
networking traffic in a cross-platform way. To use it, just
`#include <upfnetworklib/networklib.hh>`:

* it models IPv4 addresses (see UPF::NetworkLib::IPv4Address) and
  Ethernet MAC addresses (see UPF::NetworkLib::MACAddress). IPv6
  addresses are not modeled yet;

* it models packet buffers and lightweight view objects on them,
  optionally automating memory management, and providing optional
  automatic check of bounds (to avoid illegal memory accesses).
  See @ref buffers for more info;

* it provides decoder classes, attaching themselves to a
  UPF::NetworkLib::BufferView on construction and providing simplified
  read-only access to fields in headers and to a protocol's PDU for
  common networking protocols (like TCP, UDP, SCTP, etc. see for
  example UPF::NetworkLib::IPv4Decoder, UPF::NetworkLib::UDPDecoder,
  UPF::NetworkLib::GTPv1UDecoder, etc.).

  Decoders in general are not meant to be reused: they should be
  allocated on the stack, and be thrown away as soon as they aren't
  needed any more. In general, they check on construction that the
  NetworkLib::BufferView they are given is large enough to actually
  contain a packet of the protocol they decode (throwing an
  exception if they don't);

* it provides some generic interfaces to implement objects which
  consume Ethernet/IPv4 packets or are a source of Ehternet/IPv4
  packets (i.e. UPF::NetworkLib::EthPacketSource, UPF::NetworkLib::EthPacketSink,
  UPF::NetworkLib::IPv4PacketSource, UPF::NetworkLib::IPv4PacketSink);

* it provides basic types to read/write simple `.pcap` files.
  See @ref pcap for more info;

* it provides a basic framework to process network traffic: the
  virtual methods of class UPF::NetworkLib::EthPacketProcessor can be
  specialized to provide specific processing;

* it provdies utilities to encapsulate IPv4 traffic in GTPv1-U (see
  UPF::NetworkLib::GTPv1UEncap) and to encapsulate IPv4 traffic into
  Ethernet frames (see UPF::NetworkLib::IPv4PacketSink);

* it provides also small utilities like UPF::NetworkLib::Iosguard and
  UPF::NetworkLib::finally(), using RAII to simplify some tasks.

@subsubsection buffers Views on packet buffers

Instead of passing around raw pointers to buffers containing raw
packet data (and passing copies of buffers), we pass around
**references** to those buffers using types UPF::NetworkLib::BufferView
and UPF::NetworkLib::BufferWritableView.

These types are lightweight proxies wrapping a packet buffer
(either read-only or read-write), providing:

* optional automatic memory management of packet buffers via
  reference counting (a buffer can be freed automatically when it's
  not used any more);

* methods to attach a NetworkLib::BufferView (or a
  NetworkLib::BufferWritableView) to some existing buffer (no
  automatic memory management is possible in that case);

* methods to get (or set) values at a given offset in a buffer,
  optionally checking bounds. The kind of values that can be
  extracted this way include common networking types of data
  (e.g. unsigned 16-bit or 32-bit values stored in network order,
  IPv4 addresses, MAC addresses, etc.).

* methods to get sub-views from an exsting view;

* methods to copy data from/to a view;

The same buffer (or buffer part) is owned by one or more
UPF::NetworkLib::BufferView and/or UPF::NetworkLib::BufferWritableView
objects

The proper ways to obtain NetworkLib::BufferView and
UPF::NetworkLib::BufferWritableView objects are:

* via some UPF::NetworkLib::PacketBufferSizedPool: it's a template
  implementing a simple pool of buffers, all of the same size,
  giving out UPF::NetworkLib::BufferWritableView objects which are
  automatically returned to the pool when they are not used
  anymore.  NetworkLib::PacketBufferPool is a convenience type
  giving out buffers sized for common needs.

* via static method UPF::NetworkLib::BufferWritableView::makeEthBuffer()
  (allocates a single buffer on the heap, automatically deleting it
  when it's not used anymore);

* via static methods
  UPF::NetworkLib::BufferWritableView::makeNonOwningBufferWritableView()
  and UPF::NetworkLib::BufferView::makeNonOwningBufferView(), which
  attach to a buffer allocated elsewere.

  Memory management is not automatic in this case: the user is
  responsible of keeping the underlying buffer around, and freeing
  it only after there's nothing referencing it any more;

@subsubsection pcap Reading/writing .pcap files

Classes UPF::NetworkLib::PcapReader and UPF::NetworkLib::PcapWriter
provide very basic support for the `.pcap` format commonly used by
tools like Wireshark or tcpdump, without depending on `libpcap`.

The support is pretty basic, as they can read/write only
uncompressed raw Ethernet traffic or IPv4 traffic with LinuxCooked
headers (i.e. L3 traffic with a custom header).

These classes are meant mainly for testing and debugging purposes
(e.g. to feed network traffic to your program, or to save it), so
their implementation isn't particularly efficient.

On top of them we have classes UPF::NetworkLib::PcapEthReader,
UPF::NetworkLib::PcapEthWriter, UPF::NetworkLib::PcapEthWriterPlus,
UPF::NetworkLib::PcapIPv4Reader and UPF::NetworkLib::PcapIPv4Writer
(which are specializations of the interfaces for generic sources or
sinks of Ethernet/IPv4 packets).

In particular, class UPF::NetworkLib::PcapEthReader is able to read the
same `.pcap` file over and over, either endlessly or for a given
number of times.

@subsection RawSocketsLib RawSocketsLib overview

RawSocketsLib (namespace UPF::RawSocketsUtil) is a small
platform-specific library, depending on NetworkLib, providing a few
types and functions to read/write data from Linux raw sockets. To
use it, just `#include <upfrawsocketslib/rawsockets.hh>`

@subsection ASN1Lib

This is actually a C library automatically generated by the
["brchiu" fork of **ASN1c**](https://github.com/brchiu/asn1c) from
the ASN.1 description of the S1AP PDU in 3GPP TS 36.413.

Being C and autogenerated, it isn't meant to be used directly:
instead, it's used via S1APLib. It is completely self-contained and
has no external dependency.

For more information, see the ASN1c official documentation.

@subsection S1APLib S1APLib overview

S1APLib is a small library (depending on NetworkLib and ASN1Lib)
providing helpers to process/decode S1AP (a protocol used in 4G/5G
mobile networks). To use it, just `#include
<upfs1aplib/s1aplib.hh>`.

Here we can decode a S1AP-PDU (i.e. the payload of a SCTP DATA
chunk) via S1APLib::S1APDecoder, and other nested types.

In partcular, it provides the following classes:

* class UPF::S1APLib::S1APDecoder, used to decode most fields of a
  S1AP-PDU;

* other classes (like UPF::S1APLib::NASDecoder, or
  UPF::S1APLib::PDNAddressDecoder) to decode some fields of the S1AP-PDU
  which are not managed by ASN1Lib (like some Network Access
  Stratum PDUs);

* class UPF::S1APLib::S1APProcessor (a specialization of
  NetworkLib::EthPacketProcessor) which extends the processing
  chain to support S1AP in general.

@subsection UPFRouterLib UPFRouterLib overview

This is a library providing tools to analyze and process network
traffic exchanged between a eNodeB and a EPC. This means inspecting
both S1AP traffic and GTPv1-U traffic. To use it, just `#include
<upfrouterlib/upfrouterlib.hh>`.

In particular, it provides:

* class UPF::UPFRouterLib::Processor (a specialization of
  UPF::S1APLib::Processor) which provides specific support to intercept
  and process S1AP's messages exchanged when a User Equipment
  (i.e. a mobile phone) attaches to a mobile network;

* class UPF::UPFRouterLib::Router, which analyzes the raw traffic between
  4G/5G eNodeBs and EPCs to discover and keep track of information
  about User Equipment attached to a mobile network, and to
  intercept and route in a configurable way both GTPv1-U traffic
  from/to a User Equipment and plain IPv4 traffic;

* class UPF::UPFRouterLib::GTPv1UEncapSink (a specialization of
  UPF::NetworkLib::IPv4PacketSink). It encapsulates plain IPv4 traffic
  in GTPv1-U (on UDP on IPv4) according to info collected from a
  UPFRouterLib::Router.

@subsection DumperLib DumperLib overview

DumperLib is a library providing overloads of `operator<<()` to
provide (via std::ostream) a human-readable representation of most
types in other libraries.  As such, it dependes on NetworkLib,
RawSocketsLib, S1APLib and UPFRouterLib. To use it, just `#include
<upfdumperlib/dumperlib.hh>`.

This code has been made into a separate library to allow saving some
space in statically linked final executables, as dumping
human-readable representations of objects is something mainly needed
only when developing and debugging applications, and human-readable
strings used in dumping data take a fair amount of space.


