using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using SnmpSharpNet;
using System.Net;
using System.Text.RegularExpressions;
using System.Data;
using System.Net.Sockets;
using System.Threading;


namespace SNMP_Tester
{
    /// <summary>
    /// SNMPTester.xaml 的交互逻辑
    /// </summary>
    public partial class SNMPTester : Window
    {
        public SNMPTester()
        {
            InitializeComponent();
            can = new Canvas[4] { home, tongxin, server, network };
        }
        Canvas[] can ;

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }
        private void btnHome_Click_1(object sender, RoutedEventArgs e)
        {
            foreach(Canvas x in can )
            {
                x.Visibility = Visibility.Hidden;
            }
            can[0].Visibility = Visibility.Visible;
            imgNetworks.Visibility = Visibility.Hidden;
            imgServers.Visibility = Visibility.Hidden;
            imgCommunications.Visibility = Visibility.Hidden;
        }

        private void btnCommunication_Click_1(object sender, RoutedEventArgs e)
        {
            foreach (Canvas x in can)
            {
                x.Visibility = Visibility.Hidden;
            }
            can[1].Visibility = Visibility.Visible;
            imgNetworks.Visibility = Visibility.Hidden;
            imgServers.Visibility = Visibility.Hidden;
            imgCommunications.Visibility = Visibility.Visible;
        }

        private void btnServer_Click_1(object sender, RoutedEventArgs e)
        {
            foreach (Canvas x in can)
            {
                x.Visibility = Visibility.Hidden;
            }
            can[2].Visibility = Visibility.Visible;
            imgNetworks.Visibility = Visibility.Hidden;
            imgServers.Visibility = Visibility.Visible;
            imgCommunications.Visibility = Visibility.Hidden;
        }

        private void btnNetwork_Click_1(object sender, RoutedEventArgs e)
        {
            foreach (Canvas x in can)
            {
                x.Visibility = Visibility.Hidden;
            }
            can[3].Visibility = Visibility.Visible;
            imgNetworks.Visibility = Visibility.Visible;
            imgServers.Visibility = Visibility.Hidden;
            imgCommunications.Visibility = Visibility.Hidden;
        }

        private void closeBtn_Click_1(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
            this.ShowInTaskbar = false;
            this.Close();
        }

        private void minBtn_Click_1(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void btnCheck1_Click_1(object sender, RoutedEventArgs e)
        {

            try
            {
                string host = txHostIP1.Text;
                if (!IsValidIp(host))
                {
                    UMessageBox.Show("提示","IP格式不正确!请重新输入。");
                    return;
                }
                int port = 161;
                if (IsValidPort(txPort1.Text.Trim()))
                {
                    port = Convert.ToInt32(txPort1.Text);
                    if (port < 0 || port > 65535)
                    {
                        UMessageBox.Show("提示", "请输入0-65535之间的端口号!");
                        return;
                    }
                }
                else
                {
                    UMessageBox.Show("提示", "请输入0-65535之间的端口号！");
                    return;
                }
                //int snmpver = cbSnmpVer1.SelectedIndex + 1;
                int snmpver = 2;
                string comm = txComm1.Text;
                Dictionary<string, string> dic = new Dictionary<string, string>();
                //默认检测设备的sysDescr信息。
                //dic = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.1.1");
                if (IsValidOid(txOid1.Text.Trim()))
                {
                        dic = getWalkValue(host, port, snmpver, comm, txOid1.Text);

                        if (dic.Count == 0)
                        {
                            UMessageBox.Show("提示", "检测不到相关Oid信息，请检查后重试。");
                        }
                        
                        foreach (var item in dic)
                        {
                            txResult1.Text += "Oid:" + item.Key + "\n值: " + item.Value + "\n\r";
                        }                    
                }
                else
                {
                    if (!string.IsNullOrEmpty(txOid1.Text.Trim()))
                    {
                        txResult1.Text += "自定义Oid格式不正确，将进行默认查询。\n\r";
                    }
                    else
                    {
                        UMessageBox.Show("提示", "请输入OID信息后重试。");   
                    }
                    dic = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.1.1");
                    foreach (var item in dic)
                    {
                        txResult1.Text += "Oid:" + item.Key + "\n值: " + item.Value + "\n\r";
                    }
                }
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                UMessageBox.Show("提示", "检测不到相关Oid信息，请检查后重试。");
            }
        }

        #region 通过oid字符数组获得相应的值
        public static Dictionary<string, string> getOIDValue(string host, int port, int snmpver, string comm, string[] oid)
        {
            //返回变量
            Dictionary<string, string> dic = new Dictionary<string, string>();

            // SNMP community name
            OctetString community = new OctetString(comm);

            // Define agent parameters class
            AgentParameters param = new AgentParameters(community);
            // Set SNMP version to 1 (or 2)
            if (snmpver == 1)
                param.Version = SnmpVersion.Ver1;
            else
                if (snmpver == 2)
                    param.Version = SnmpVersion.Ver2;
            // Construct the agent address object
            // IpAddress class is easy to use here because
            //  it will try to resolve constructor parameter if it doesn't
            //  parse to an IP address
            IpAddress agent = new IpAddress(host);

            // Construct target
            UdpTarget target = new UdpTarget((IPAddress)agent, port, 2000, 1);

            // Pdu class used for all requests
            Pdu pdu = new Pdu(PduType.Get);

            foreach (string singleoid in oid)
            {
                pdu.VbList.Add(singleoid);
            }
            try
            {
                if (snmpver == 1)
                {
                    // Make SNMP request
                    SnmpV1Packet result = (SnmpV1Packet)target.Request(pdu, param);

                    // If result is null then agent didn't reply or we couldn't parse the reply.
                    if (result != null)
                    {
                        // ErrorStatus other then 0 is an error returned by 
                        // the Agent - see SnmpConstants for error definitions
                        if (result.Pdu.ErrorStatus == 0)
                        {
                            for (int i = 0; i < result.Pdu.VbList.Count; i++)
                            {
                                dic.Add(result.Pdu.VbList[i].Oid.ToString(), result.Pdu.VbList[i].Value.ToString());
                            }
                            // Reply variables are returned in the same order as they were added
                            //  to the VbList
                        }
                    }

                }
                else
                {
                    // Make SNMP request
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);

                    // If result is null then agent didn't reply or we couldn't parse the reply.
                    if (result != null)
                    {
                        // ErrorStatus other then 0 is an error returned by 
                        // the Agent - see SnmpConstants for error definitions
                        if (result.Pdu.ErrorStatus == 0)
                        {
                            for (int i = 0; i < result.Pdu.VbList.Count; i++)
                            {
                                dic.Add(result.Pdu.VbList[i].Oid.ToString(), result.Pdu.VbList[i].Value.ToString());
                            }
                            // Reply variables are returned in the same order as they were added
                            //  to the VbList
                        }
                    }

                }
                target.Close();
                return dic;
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                target.Close();
                return dic;
            }
        }
        #endregion

        #region 通过snmpwalk返回oid根下面的所有值
        public static Dictionary<string, string> getWalkValue(string host, int port, int snmpver, string comm, string irootOid)
        {
            Dictionary<string, string> dic = new Dictionary<string, string>();
            // SNMP community name
            OctetString community = new OctetString(comm);

            // Define agent parameters class
            AgentParameters param = new AgentParameters(community);
            // Set SNMP version to 2 (GET-BULK only works with SNMP ver 2 and 3)
            if (snmpver == 2)
                param.Version = SnmpVersion.Ver2;
            else
                param.Version = SnmpVersion.Ver3;
            // Construct the agent address object
            // IpAddress class is easy to use here because
            //  it will try to resolve constructor parameter if it doesn't
            //  parse to an IP address
            IpAddress agent = new IpAddress(host);

            // Construct target
            UdpTarget target = new UdpTarget((IPAddress)agent, port, 2000, 1);

            // Define Oid that is the root of the MIB
            //  tree you wish to retrieve
            Oid rootOid = new Oid(irootOid); // ifDescr

            // This Oid represents last Oid returned by
            //  the SNMP agent
            Oid lastOid = (Oid)rootOid.Clone();

            // Pdu class used for all requests
            Pdu pdu = new Pdu(PduType.GetBulk);

            // In this example, set NonRepeaters value to 0
            pdu.NonRepeaters = 0;
            // MaxRepetitions tells the agent how many Oid/Value pairs to return
            // in the response.
            pdu.MaxRepetitions = 1000;
            try
            {
                // Loop through results
                while (lastOid != null)
                {
                    // When Pdu class is first constructed, RequestId is set to 0
                    // and during encoding id will be set to the random value
                    // for subsequent requests, id will be set to a value that
                    // needs to be incremented to have unique request ids for each
                    // packet
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    // Clear Oids from the Pdu class.
                    pdu.VbList.Clear();
                    // Initialize request PDU with the last retrieved Oid
                    pdu.VbList.Add(lastOid);
                    if (snmpver == 2)
                    {
                        // Make SNMP request
                        SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                        // You should catch exceptions in the Request if using in real application.
                        // If result is null then agent didn't reply or we couldn't parse the reply.
                        if (result != null)
                        {
                            // ErrorStatus other then 0 is an error returned by 
                            // the Agent - see SnmpConstants for error definitions
                            if (result.Pdu.ErrorStatus == 0)
                            {
                                // Walk through returned variable bindings
                                foreach (Vb v in result.Pdu.VbList)
                                {
                                    // Check that retrieved Oid is "child" of the root OID
                                    if (rootOid.IsRootOf(v.Oid))
                                    {
                                        dic.Add(v.Oid.ToString(), v.Value.ToString());
                                    }
                                    else
                                    {
                                        // we have reached the end of the requested
                                        // MIB tree. Set lastOid to null and exit loop
                                        lastOid = null;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        // Make SNMP request
                        SnmpV3Packet result = (SnmpV3Packet)target.Request(pdu, param);
                        // You should catch exceptions in the Request if using in real application.
                        // If result is null then agent didn't reply or we couldn't parse the reply.
                        // If result is null then agent didn't reply or we couldn't parse the reply.
                        if (result != null)
                        {
                            // ErrorStatus other then 0 is an error returned by 
                            // the Agent - see SnmpConstants for error definitions
                            if (result.Pdu.ErrorStatus == 0)
                            {
                                // Walk through returned variable bindings
                                foreach (Vb v in result.Pdu.VbList)
                                {
                                    // Check that retrieved Oid is "child" of the root OID
                                    if (rootOid.IsRootOf(v.Oid))
                                    {
                                        dic.Add(v.Oid.ToString(), v.Value.ToString());
                                    }
                                    else
                                    {
                                        // we have reached the end of the requested
                                        // MIB tree. Set lastOid to null and exit loop
                                        lastOid = null;
                                    }
                                }
                            }
                        }
                    }
                }
                target.Close();
                return dic;
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                target.Close();
                return dic;
            }
        }
        #endregion

        #region 通过snmpwalk返回oid根下面的所有值,支持版本3
        public static Dictionary<string, string> getWalkValue_v3(string host, int port, int snmpver, string comm, string irootOid)
        {
            Dictionary<string, string> dic = new Dictionary<string, string>();
            // SNMP community name
            OctetString community = new OctetString(comm);

            // Define agent parameters class
            AgentParameters param = new AgentParameters(community);
            // Set SNMP version to 2 (GET-BULK only works with SNMP ver 2 and 3)
            param.Version = SnmpVersion.Ver3;
            // Construct the agent address object
            // IpAddress class is easy to use here because
            //  it will try to resolve constructor parameter if it doesn't
            //  parse to an IP address
            IpAddress agent = new IpAddress(host);

            // Construct target
            UdpTarget target = new UdpTarget((IPAddress)agent, port, 2000, 1);

            // Define Oid that is the root of the MIB
            //  tree you wish to retrieve
            Oid rootOid = new Oid(irootOid); // ifDescr

            // This Oid represents last Oid returned by
            //  the SNMP agent
            Oid lastOid = (Oid)rootOid.Clone();

            // Pdu class used for all requests
            Pdu pdu = new Pdu(PduType.GetBulk);

            // In this example, set NonRepeaters value to 0
            pdu.NonRepeaters = 0;
            // MaxRepetitions tells the agent how many Oid/Value pairs to return
            // in the response.
            pdu.MaxRepetitions = 1000;
            try
            {
                // Loop through results
                while (lastOid != null)
                {
                    // When Pdu class is first constructed, RequestId is set to 0
                    // and during encoding id will be set to the random value
                    // for subsequent requests, id will be set to a value that
                    // needs to be incremented to have unique request ids for each
                    // packet
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    // Clear Oids from the Pdu class.
                    pdu.VbList.Clear();
                    // Initialize request PDU with the last retrieved Oid
                    pdu.VbList.Add(lastOid);
                    // Make SNMP request
                    SnmpV3Packet result = new SnmpV3Packet();
                    result.authPriv(ASCIIEncoding.UTF8.GetBytes("milan"),
                        ASCIIEncoding.UTF8.GetBytes("myAuthSecret"), AuthenticationDigests.MD5,
                        ASCIIEncoding.UTF8.GetBytes("myPrivSecret"), PrivacyProtocols.DES);
                    result = (SnmpV3Packet)target.Request(pdu, param);
                    // You should catch exceptions in the Request if using in real application.
                    // If result is null then agent didn't reply or we couldn't parse the reply.
                    if (result != null)
                    {
                        // ErrorStatus other then 0 is an error returned by 
                        // the Agent - see SnmpConstants for error definitions
                        if (result.Pdu.ErrorStatus == 0)
                        {
                            // Walk through returned variable bindings
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    dic.Add(v.Oid.ToString(), v.Value.ToString());
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                            }
                        }
                    }

                }
                target.Close();
                return dic;
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                target.Close();
                return dic;
            }
        }
        #endregion

        /// <summary>
        /// 正则验证IP地址格式
        /// </summary>
        /// <param name="strIn"></param>
        /// <returns></returns>
        bool IsValidIp(string strIn)
        {
            return Regex.IsMatch(strIn, @"((25[0-5])|(2[0-4]\d)|(1\d\d)|([1-9]\d)|\d)(\.((25[0-5])|(2[0-4]\d)|(1\d\d)|([1-9]\d)|\d)){3}");
        }

        /// <summary>
        /// 正则验证Oid格式
        /// </summary>
        /// <param name="strIn"></param>
        /// <returns></returns>
        private static bool IsValidOid(string value)
        {
            Regex r = new Regex(@"^[0-9.]+$");

            return r.Match(value).Success;
        }

        /// <summary>
        /// 正则验证Oid格式
        /// </summary>
        /// <param name="strIn"></param>
        /// <returns></returns>
        private static bool IsValidPort(string value)
        {
            Regex r = new Regex(@"^[0-9]+$");

            return r.Match(value).Success;
        }


        private void btnCheck2_Click_1(object sender, RoutedEventArgs e)
        {
            try
            {
                string host = txHostIP2.Text;
                if (!IsValidIp(host))
                {
                    UMessageBox.Show("提示", "IP格式不正确!请重新输入。");
                    return;
                }
                int port = 161;
                if (IsValidPort(txPort2.Text.Trim()))
                {
                    port = Convert.ToInt32(txPort2.Text);
                    if (port < 0 || port > 65535)
                    {
                        UMessageBox.Show("提示", "请输入0-65535之间的端口号!");
                        return;
                    }
                }
                else
                {
                    UMessageBox.Show("提示", "请输入0-65535之间的端口号！");
                    return;
                }
                int snmpver = 2;
                string comm = txComm2.Text;
                int type = 0;
                //系统描述
                Dictionary<string, string> sysInfo = new Dictionary<string, string>();
                    sysInfo = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.1.1");
                    type = sysInfo["1.3.6.1.2.1.1.1.0"].ToLower().IndexOf("windows");
                    txResult2.Text += "系统描述:" + sysInfo["1.3.6.1.2.1.1.1.0"] + "\n\r";               
                if (IsValidOid(txOid2.Text.Trim()))
                {
                    //自定义OID
                    Dictionary<string, string> customInfo = new Dictionary<string, string>();
                    customInfo = getWalkValue(host, port, snmpver, comm, txOid2.Text.Trim());
                    foreach (var item in customInfo)
                    {
                        txResult2.Text += txOid3.Text + ":" + item.Value + "\n\r";
                    }
                }
                else
                {
                    if (!string.IsNullOrEmpty(txOid2.Text.Trim()))
                    {
                        txResult2.Text += "自定义Oid格式不正确，将进行默认查询。\n\r";
                    }
                    //CPU使用情况
                    Dictionary<string, string> cpu = new Dictionary<string, string>();
                    cpu = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.25.3.3.1.2");
                    double sum = 0;
                    foreach (var item in cpu)
                    {
                        sum += Convert.ToInt16(item.Value);
                    }
                    txResult2.Text += "cpu使用率:" + (sum / cpu.Count) + "%\r";
                    txResult2.Text += "cpu核心数:" + cpu.Count + "个\n\r";

                    //进程数
                    Dictionary<string, string> process = new Dictionary<string, string>();
                    process = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.25.1.6");
                    foreach (var item in process)
                    {
                        txResult2.Text += "进程数:" + item.Value + "\n\r";
                    }
                    int i = 0;
                    if (type == -1)
                    {
                        //CPU负载
                        Dictionary<string, string> cpu_load = new Dictionary<string, string>();
                        cpu_load = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.2021.10.1.3");
                        string[] load = new string[cpu_load.Count];
                        foreach (string val in cpu_load.Values)
                        {
                            load[i] = val;
                            i++;
                        }
                        txResult2.Text += "cpu最近1分钟负载:" + load[0] + "个\r";
                        txResult2.Text += "cpu最近5分钟负载:" + load[1] + "个\r";
                        txResult2.Text += "cpu最近15分钟负载:" + load[2] + "个\n\r";

                        //swap换入换出速率
                        Dictionary<string, string> swap = new Dictionary<string, string>();
                        swap = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.2021.11.3");
                        txResult2.Text += "swap换入速率:" + swap["1.3.6.1.4.1.2021.11.3.0"] + "B/s\r";
                        swap = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.2021.11.4");
                        txResult2.Text += "swap换出速率:" + swap["1.3.6.1.4.1.2021.11.4.0"] + "B/s\n\r";
                    }

                    //硬盘和内存使用情况
                    Dictionary<string, string> disk_memory_desc = new Dictionary<string, string>();
                    int num = 0;
                    string disk_tag = "";
                    string memory_tag = "";
                    string virtualmemory_tag = "";
                    disk_memory_desc = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.25.2.3.1.2");//硬盘，内存描述                
                    foreach (var item in disk_memory_desc)
                    {
                        if (item.Value == "1.3.6.1.2.1.25.2.1.2")
                            memory_tag += num.ToString() + ",";//记录物理内存下标
                        if (item.Value == "1.3.6.1.2.1.25.2.1.3")
                            virtualmemory_tag += num.ToString() + ",";//记录虚拟内存下标
                        if (item.Value == "1.3.6.1.2.1.25.2.1.4")
                            disk_tag += num.ToString() + ",";//记录硬盘分区下标
                        num++;
                    }
                    string[] memoryTag = memory_tag.Substring(0, memory_tag.Length - 1).Split(',');//将物理内存下标记录转换为数组
                    string[] virtualmemoryTag = virtualmemory_tag.Substring(0, virtualmemory_tag.Length - 1).Split(',');//将虚拟内存下标记录转换为数组
                    string[] diskTag = disk_tag.Substring(0, disk_tag.Length - 1).Split(',');//将硬盘分区下标记录转换为数组
                    Dictionary<string, string> disk_memory_name = new Dictionary<string, string>();
                    disk_memory_name = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.25.2.3.1.3");//盘符
                    string[] name = new string[disk_memory_name.Count];
                    i = 0;
                    foreach (string val in disk_memory_name.Values)
                    {
                        name[i] = val;
                        i++;
                    }

                    Dictionary<string, string> disk_memory_bytes = new Dictionary<string, string>();
                    disk_memory_bytes = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.25.2.3.1.4");//每个块占的字节数
                    string[] bytes = new string[disk_memory_name.Count];
                    i = 0;
                    foreach (string val in disk_memory_bytes.Values)
                    {
                        bytes[i] = val;
                        i++;
                    }

                    Dictionary<string, string> disk_memory_total = new Dictionary<string, string>();
                    disk_memory_total = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.25.2.3.1.5");//总共占有的块数
                    string[] total = new string[disk_memory_name.Count];
                    i = 0;
                    foreach (string val in disk_memory_total.Values)
                    {
                        total[i] = val;
                        i++;
                    }

                    Dictionary<string, string> disk_memory_used = new Dictionary<string, string>();
                    disk_memory_used = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.25.2.3.1.6");//已使用的块数
                    string[] used = new string[disk_memory_name.Count];
                    i = 0;
                    foreach (string val in disk_memory_used.Values)
                    {
                        used[i] = val;
                        i++;
                    }

                    //内存总数
                    int t = Convert.ToInt32(memoryTag[0]);
                    double memory_sum = Convert.ToDouble(total[t]) * Convert.ToDouble(bytes[t]);
                    //内存已用数
                    double memory_used = Convert.ToDouble(used[t]) * Convert.ToDouble(bytes[t]);
                    //内存使用率
                    double memory_usage = Convert.ToDouble(used[t]) / Convert.ToDouble(total[t]);
                    txResult2.Text += "内存总数:" + conversionByte(memory_sum) + "\r";
                    txResult2.Text += "内存已用数:" + conversionByte(memory_used) + "\r";
                    txResult2.Text += "内存使用率:" + memory_usage.ToString("P") + "\n\r";

                    t = Convert.ToInt32(virtualmemoryTag[0]);
                    //虚拟内存总数
                    double virtualmemory_sum = Convert.ToDouble(total[t]) * Convert.ToDouble(bytes[t]);
                    //虚拟内存已用数
                    double virtualmemory_used = Convert.ToDouble(used[t]) * Convert.ToDouble(bytes[t]);
                    //虚拟内存使用率
                    double virtualmemory_usage = 0;
                    if (Convert.ToDouble(total[t]) != 0)
                        virtualmemory_usage = Convert.ToDouble(used[t]) / Convert.ToDouble(total[t]);
                    txResult2.Text += "虚拟内存总数:" + conversionByte(virtualmemory_sum) + "\r";
                    txResult2.Text += "虚拟内存已用数:" + conversionByte(virtualmemory_used) + "\r";
                    txResult2.Text += "虚拟内存使用率:" + virtualmemory_usage.ToString("P") + "\n\r";

                    //硬盘总容量
                    double _disk_sum = 0;
                    //硬盘总已用空间
                    double _disk_used = 0;
                    //硬盘总使用率
                    double _disk_usage = 0;
                    for (int j = 0; j < diskTag.Length; j++)
                    {
                        t = Convert.ToInt32(diskTag[j]);
                        //硬盘总数
                        double disk_sum = Convert.ToDouble(total[t]) * Convert.ToDouble(bytes[t]);
                        //硬盘已用数
                        double disk_used = Convert.ToDouble(used[t]) * Convert.ToDouble(bytes[t]);
                        //硬盘使用率
                        double disk_usage = Convert.ToDouble(used[t]) / Convert.ToDouble(total[t]);
                        _disk_sum += disk_sum;
                        _disk_used += disk_used;
                        if (type == -1)
                        {
                            txResult2.Text += "(" + name[t] + ")" + "容量:" + conversionByte(disk_sum) + "\r";
                            txResult2.Text += "(" + name[t] + ")" + "已用空间:" + conversionByte(disk_used) + "\r";
                            txResult2.Text += "(" + name[t] + ")" + "使用率:" + disk_usage.ToString("P") + "\n\r";
                        }
                        else
                        {
                            txResult2.Text += "(" + name[t].Substring(0, 2) + ")" + "容量:" + conversionByte(disk_sum) + "\r";
                            txResult2.Text += "(" + name[t].Substring(0, 2) + ")" + "已用空间:" + conversionByte(disk_used) + "\r";
                            txResult2.Text += "(" + name[t].Substring(0, 2) + ")" + "使用率:" + disk_usage.ToString("P") + "\n\r";
                        }
                    }
                    _disk_usage = _disk_used / _disk_sum;
                    txResult2.Text += "硬盘总容量:" + conversionByte(_disk_sum) + "\r";
                    txResult2.Text += "硬盘总已用空间:" + conversionByte(_disk_used) + "\r";
                    txResult2.Text += "硬盘总使用率:" + _disk_usage.ToString("P") + "\n\r";
                }
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                UMessageBox.Show("提示", "检测不到相关Oid信息，请检查后重试。");
            }
        }

        private void btnCheck3_Click_1(object sender, RoutedEventArgs e)
        {
            try
            {
                string host = txHostIP3.Text;
                if (!IsValidIp(host))
                {
                    UMessageBox.Show("提示", "IP格式不正确!请重新输入。");
                    return;
                }
                int port = 161;
                if (IsValidPort(txPort3.Text.Trim()))
                {
                    port = Convert.ToInt32(txPort3.Text);
                    if (port < 0 || port > 65535)
                    {
                        UMessageBox.Show("提示", "请输入0-65535之间的端口号!");
                        return;
                    }
                }
                else
                {
                    UMessageBox.Show("提示", "请输入0-65535之间的端口号！");
                    return;
                }
                int snmpver = 2;
                string comm = txComm3.Text;
                //系统描述
                Dictionary<string, string> sysInfo = new Dictionary<string, string>();
                sysInfo = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.1.1");
                txResult3.Text += "系统描述:" + sysInfo["1.3.6.1.2.1.1.1.0"] + "\n\r";

                if (IsValidOid(txOid3.Text.Trim()))
                {
                    //自定义OID
                    Dictionary<string, string> customInfo = new Dictionary<string, string>();
                    customInfo = getWalkValue(host, port, snmpver, comm, txOid3.Text.Trim());
                    foreach (var item in customInfo)
                    {
                        txResult3.Text += txOid3.Text + ":" + item.Value + "\n\r";
                    }
                }
                else
                {
                    if (!string.IsNullOrEmpty(txOid3.Text.Trim()))
                    {
                        txResult3.Text += "自定义Oid格式不正确，将进行默认查询。\n\r";
                    }
                    //获取端口Index
                    int i = 0;
                    Dictionary<string, string> port_index = new Dictionary<string, string>();
                    port_index = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.2.2.1.1");
                    string[] index = new string[port_index.Count];
                    foreach (string val in port_index.Values)
                    {
                        index[i] = val;
                        i++;
                    }

                    i = 0;
                    Dictionary<string, string> bytes_in = new Dictionary<string, string>();
                    bytes_in = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.2.2.1.10");
                    string[] portin = new string[bytes_in.Count];
                    foreach (string val in bytes_in.Values)
                    {
                        portin[i] = val;
                        i++;
                    }

                    i = 0;
                    Dictionary<string, string> bytes_out = new Dictionary<string, string>();
                    bytes_out = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.2.2.1.16");
                    string[] portout = new string[bytes_out.Count];
                    foreach (string val in bytes_out.Values)
                    {
                        portout[i] = val;
                        i++;
                    }
                    Thread.Sleep(5000);//等待一段时间
                    i = 0;
                    Dictionary<string, string> _bytes_in = new Dictionary<string, string>();
                    _bytes_in = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.2.2.1.10");
                    string[] _portin = new string[_bytes_in.Count];
                    foreach (string val in bytes_in.Values)
                    {
                        _portin[i] = val;
                        i++;
                    }
                    for (int j = 0; j < _portin.Length; j++)
                    {
                        txResult3.Text += "端口[" + index[j] + "]入流量:" + conversionByte(Convert.ToDouble(_portin[j])) + "\r";
                        txResult3.Text += "端口[" + index[j] + "]入速率:" + (Convert.ToDouble(_portin[j]) - Convert.ToDouble(portin[j])) / 5 + "Bytes/s\r";
                    }

                    txResult3.Text += "\r\n";
                    i = 0;
                    Dictionary<string, string> _bytes_out = new Dictionary<string, string>();
                    _bytes_out = getWalkValue(host, port, snmpver, comm, "1.3.6.1.2.1.2.2.1.16");
                    string[] _portout = new string[_bytes_out.Count];
                    foreach (string val in bytes_out.Values)
                    {
                        _portout[i] = val;
                        i++;
                    }
                    for (int j = 0; j < _portout.Length; j++)
                    {
                        txResult3.Text += "端口[" + index[j] + "]出流量:" + conversionByte(Convert.ToDouble(_portout[j])) + "\r";
                        txResult3.Text += "端口[" + index[j] + "]出速率:" + (Convert.ToDouble(_portout[j]) - Convert.ToDouble(portout[j])) / 5 + "Bytes/s\r";
                    }

                    //if (chVendor3.SelectedIndex == 0)
                    //{
                    //    //内存使用情况
                    //    Dictionary<string, string> memory = new Dictionary<string, string>();
                    //    memory = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.9.48.1.1.1.6");
                    //    //内存空闲数
                    //    double memory_free = Convert.ToDouble(memory["1.3.6.1.4.1.9.9.48.1.1.1.6.0"]);
                    //    memory = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.9.48.1.1.1.5");
                    //    //内存已用数
                    //    double memory_used = Convert.ToDouble(memory["1.3.6.1.4.1.9.9.48.1.1.1.5.0"]);
                    //    //内存使用率
                    //    double memory_usage = memory_used / (memory_free + memory_used);
                    //    txResult2.Text += "内存总数:" + conversionByte(memory_free + memory_used) + "\r";
                    //    txResult2.Text += "内存已用数:" + conversionByte(memory_used) + "\r";
                    //    txResult2.Text += "内存使用率:" + memory_usage.ToString("P") + "\n\r";

                    //    //cpu总使用率
                    //    Dictionary<string, string> cpu = new Dictionary<string, string>();
                    //    //5秒钟cpu总使用率
                    //    cpu = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.2.1.56.0");
                    //    txResult2.Text += "5秒钟cpu总使用率:" + cpu["1.3.6.1.4.1.9.2.1.56.0"] + "\r";
                    //    //1分钟cpu总使用率
                    //    cpu = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.2.1.57.0");
                    //    txResult2.Text += "1分钟cpu总使用率:" + cpu["1.3.6.1.4.1.9.2.1.57.0"] + "\r";
                    //    //5分钟cpu总使用率
                    //    cpu = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.2.1.58.0");
                    //    txResult2.Text += "5分钟cpu总使用率:" + cpu["1.3.6.1.4.1.9.2.1.58.0"] + "\n\r";

                    //    //cpu总负载
                    //    Dictionary<string, string> cpuload = new Dictionary<string, string>();
                    //    //1分钟cpu总负载
                    //    cpuload = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.9.109.1.1.1.1.24");
                    //    txResult2.Text += "1分钟cpu总负载:" + cpuload["1.3.6.1.4.1.9.9.109.1.1.1.1.24"] + "\r";
                    //    //5分钟cpu总负载
                    //    cpuload = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.9.109.1.1.1.1.25");
                    //    txResult2.Text += "5分钟cpu总负载:" + cpuload["1.3.6.1.4.1.9.9.109.1.1.1.1.25"] + "\r";
                    //    //15分钟cpu总负载
                    //    cpuload = getWalkValue(host, port, snmpver, comm, "1.3.6.1.4.1.9.9.109.1.1.1.1.26");
                    //    txResult2.Text += "15分钟cpu总负载:" + cpuload["1.3.6.1.4.1.9.9.109.1.1.1.1.26"] + "\n\r";

                    //}
                }
            }
            catch (Exception ex)
            {
                ex.Message.ToString();
                UMessageBox.Show("提示", "检测不到相关Oid信息，请检查后重试。");
            }
        }

        public static String conversionByte(double bytes)
        {
            int unit = 1024;
            if (bytes < unit) return bytes + " B";
            int exp = (int)(Math.Log(bytes) / Math.Log(unit));
            return String.Format("{0:F1} {1}B", bytes / Math.Pow(unit, exp), "KMGTPE"[exp - 1]);

        }

      
    }
}
