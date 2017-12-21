using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using System.Threading;
using System.Collections;

namespace PaketGonderme
{
    class Program
    {

        static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
        static PacketDevice selectedDevice = allDevices[0];
        static System.Byte MesajID=0;
        static void Main(string[] args)
        {
            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (Açıklama Yok)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Ağ Aygıtını Seç (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);
            selectedDevice = allDevices[deviceIndex - 1];

            Thread trGonder = new Thread(new ThreadStart(KomutGonder));
            Thread trDinle = new Thread(new ThreadStart(Dinle));
            trGonder.Start();
            trDinle.Start();
            
        }
        private static void KomutGonder()
        {
            

            string komut = "";

            while (komut != "ç")
            {
                Console.WriteLine("Gönderilecek Komutu Girin: ");
                komut = Console.ReadLine();
                byte[] jeton = { 5, 5, 5, 5, 5, 5, 5, 5, 5, 5 };
                // Version-Type-Token Length-Code-Message ID-Token-Payload
                Gonder(1,1,10,3,1555,jeton,komut);
                Thread.Sleep(2000);
                // Open the output device
            }
        }

        private static Packet BuildUdpPacket(byte[] yuk)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("01:01:01:01:01:01"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            UdpLayer udpLayer =
                new UdpLayer
                {
                    SourcePort = 4050,
                    DestinationPort = 6666,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(yuk),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }
        private static void Gonder(byte Ver, byte T, byte TKL, byte Code, Int16 MessageID, byte[] Token, string PayloadSTR)
        {

            System.Byte[] Payload = {};
            System.Byte[] CoApPacket = { };
            System.Byte Ver_T_TKL = 0;
            byte dolgu=255;
            //---------------------------------------------------
            if (Ver == 1) Ver = 64;
            //---------------------------------------------------
            if (T == 0) { /* zaten varsayılan olarak seçili*/}
            else if (T == 1) { T = 16; } // Non-Confirmable
            else if (T == 2) { T = 32; } // Acknowledgement
            else                     { T = 48; } // Reset
            //---------------------------------------------------
            byte[] intBytes = BitConverter.GetBytes(MessageID);
            //Array.Reverse(intBytes);
            byte[] MID = intBytes;
            //---------------------------------------------------
            Payload = System.Text.Encoding.ASCII.GetBytes(PayloadSTR);
            Ver_T_TKL = (byte)(Ver + T + TKL);


            List<byte> bytelistesi1 = new List<byte>();

            bytelistesi1.Add(Ver_T_TKL);
            bytelistesi1.Add(Code);
            bytelistesi1.AddRange(MID);
            bytelistesi1.AddRange(Token);
            bytelistesi1.Add(dolgu);
            bytelistesi1.AddRange(Payload);
            
            CoApPacket = bytelistesi1.ToArray(); // listeden tekrar diziye çevir.

            using (PacketCommunicator communicator = selectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                communicator.SendPacket(BuildUdpPacket(CoApPacket));
            }
        }


        private static void Dinle()
        {

            using (PacketCommunicator communicator =
                selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and udp"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }
        }
        private static void PacketHandler(Packet packet)
        {
            // print timestamp and length of the packet
            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);

            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;

            // print ip addresses and udp ports
            if (ip.Destination.ToString() == "11.22.33.44" && udp.DestinationPort.ToString()=="6666")
            {
                System.Byte[] bytes = udp.Payload.ToArray<byte>();
                System.Byte[] TokenBytes = { };
                System.Byte[] Payloadbytes ={ };
                //------------------------------------------------------
                System.Byte Ver_T_TKL = bytes[0];
                System.Byte Code = bytes[1];
                System.Byte[] MID = { bytes[2], bytes[3] };
                UInt16 MesajID = BitConverter.ToUInt16(MID, 0);
                //------------------------------------------------------
                string CoApVersiyonu="";
                string komuttipi = "";
                if (Ver_T_TKL < 128)
                {
                    CoApVersiyonu = "CoAp Versiyon 1";
                    Ver_T_TKL -= 64;
                }
                //-------------------------------------------------------------------------------
                if (Ver_T_TKL >= 48) { komuttipi = "Reset"; Ver_T_TKL -= 48; }
                else if (Ver_T_TKL >= 32) { komuttipi = "Acknowledgement"; Ver_T_TKL -= 32; } 
                else if (Ver_T_TKL >= 16) { komuttipi = "non-Confirmable"; Ver_T_TKL -= 16; }
                else                          { komuttipi = "Confirmable"; }
                //--------------------------------------------------------------------------------
                List<byte> bytelistesiToken = new List<byte>();
                byte TokenLength = Ver_T_TKL;
                for (int i = 0; i < TokenLength; i++) bytelistesiToken.Add(bytes[i+4]); // ilk 4 byte VER T TKL Code MEssage ID. TOKEN dördüncüden başlar
                TokenBytes = bytelistesiToken.ToArray();
                //-------------------------------------------------------------------------
                // bytes[TokenLength+3] dolgu 1111111. Bu byte'ı atla.
                //-------------------------------------------------------------------------
                List<byte> bytelistesiPayload = new List<byte>();
                for (int i = TokenLength + 5; i < bytes.Length; i++) bytelistesiPayload.Add(bytes[i]);
                Payloadbytes = bytelistesiPayload.ToArray();
                String Payload = Encoding.ASCII.GetString(Payloadbytes);
                //-------------------------------------------------------------------------------------

                //istek yeni;
                //yeni.ip = ip.Source;
                //yeni.port = udp.SourcePort.ToString();
                //yeni.komuttipi = komuttipi;
                //yeni.komut = komut;
                //Komutlar.Enqueue(yeni);

                Console.WriteLine("########---- KOMUT ALINDI ----#########");
                Console.WriteLine(ip.Source + ":" + udp.SourcePort + " -> " + ip.Destination + ":" + udp.DestinationPort);
                Console.WriteLine("CoAP Sürümü: " + CoApVersiyonu);
                Console.WriteLine("Kod: " + Code);
                Console.WriteLine("Mesaj ID: " + MesajID);
                Console.WriteLine("Komut Tipi: " + komuttipi);
                Console.WriteLine("Gelen Komut: " + Payload);
                Console.WriteLine("########---- SON ----#########");



            }
        }

    }
}
