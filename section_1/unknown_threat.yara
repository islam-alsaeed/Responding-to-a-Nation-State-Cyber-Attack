rule unknown_threat {
        meta:
                Author = "@islam"
                Description = "the rule detects one more malware "
        strings:
                $coma = "chkconfig iptables off"
                $mode = "chmod +x /tmp/SSH-T"
		$domain = "http://darkl0rd.com:7758"
        condition:
                all of them

}
