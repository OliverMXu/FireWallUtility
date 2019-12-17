using NetFwTypeLib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FirewallUtility
{
    public partial class MainForm : Form
    {
        INetFwPolicy2 policy2 = null;

        public MainForm()
        {
            InitializeComponent();
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            policy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
        }

        public static bool CreateOutRule(NET_FW_IP_PROTOCOL_ type, string ruleName, string appPath, string localAddresses = null, string localPorts = null, string remoteAddresses = null, string remotePorts = null)
        {
            //创建防火墙策略类的实例
            INetFwPolicy2 policy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            //检查是否有同名规则
            foreach (INetFwRule item in policy2.Rules)
            {
                if (item.Name == ruleName)
                {
                    return true;
                }
            }
            //创建防火墙规则类的实例: 有关该接口的详细介绍：https://docs.microsoft.com/zh-cn/windows/win32/api/netfw/nn-netfw-inetfwrule
            INetFwRule rule = (INetFwRule)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
            //为规则添加名称
            rule.Name = ruleName;
            //为规则添加描述
            rule.Description = "禁止程序访问非指定端口";
            //选择入站规则还是出站规则，IN为入站，OUT为出站
            rule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT;
            //为规则添加协议类型
            rule.Protocol = (int)type;
            //为规则添加应用程序（注意这里是应用程序的绝对路径名）
            rule.ApplicationName = appPath;
            //为规则添加本地IP地址    
            if (!string.IsNullOrEmpty(localAddresses))
            {
                rule.LocalAddresses = localAddresses;
            }

            //为规则添加本地端口
            if (!string.IsNullOrEmpty(localPorts))
            {
                //需要移除空白字符（不能包含空白字符，下同）
                rule.LocalPorts = localPorts.Replace(" ", "");// "1-29999, 30003-33332, 33334-55554, 55556-60004, 60008-65535";
            }
            //为规则添加远程IP地址
            if (!string.IsNullOrEmpty(remoteAddresses))
            {
                rule.RemoteAddresses = remoteAddresses;
            }
            //为规则添加远程端口
            if (!string.IsNullOrEmpty(remotePorts))
            {
                rule.RemotePorts = remotePorts.Replace(" ", "");
            }
            //设置规则是阻止还是允许（ALLOW=允许，BLOCK=阻止）
            rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            //分组 名
            rule.Grouping = "GroupsName";

            rule.InterfaceTypes = "All";
            //是否启用规则
            rule.Enabled = true;
            try
            {
                //添加规则到防火墙策略
                policy2.Rules.Add(rule);
            }
            catch (Exception e)
            {
                string error = $"防火墙添加规则出错：{ruleName} {e.Message}";
                throw new Exception(error);
            }
            return true;
        }
        /// <summary>
        /// 为WindowsDefender防火墙添加一条U3D通信TCP端口出站规则
        /// </summary>
        /// <param name="appPath">应用程序完整路径</param>
        /// <param name="localAddresses">本地地址</param>
        /// <param name="localPorts">本地端口</param>
        /// <param name="remoteAddresses">远端地址</param>
        /// <param name="remotePorts">远端端口</param>
        public static bool CreateTCPOutRule(string appPath, string localAddresses = null, string localPorts = null, string remoteAddresses = null, string remotePorts = null)
        {
            try
            {
                string ruleName = $"{System.IO.Path.GetFileNameWithoutExtension(appPath)}TCP";
                CreateOutRule(NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP, ruleName, appPath, localAddresses, localPorts, remoteAddresses, remotePorts);

            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
            return true;
        }
        /// <summary>
        /// 为WindowsDefender防火墙添加一条通信UDP端口出站规则
        /// </summary>
        /// <param name="appPath">应用程序完整路径</param>
        /// <param name="localAddresses">本地地址</param>
        /// <param name="localPorts">本地端口</param>
        /// <param name="remoteAddresses">远端地址</param>
        /// <param name="remotePorts">远端端口</param>
        public static bool CreateUDPOutRule(string appPath, string localAddresses = null, string localPorts = null, string remoteAddresses = null, string remotePorts = null)
        {
            try
            {
                string ruleName = $"{System.IO.Path.GetFileNameWithoutExtension(appPath)}UDP";
                CreateOutRule(NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_UDP, ruleName, appPath, localAddresses, localPorts, remoteAddresses, remotePorts);

            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
            return true;
        }
    }
}
