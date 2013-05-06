struct dionaeaEvent {
	unsigned int dionaea;
	unsigned int reference;
	char* localIP;
	char* remoteIP;
	unsigned int localPort;
	unsigned int remotePort;
	char* transport;
	char* incident;
	char* type;
	char* protocol;
	unsigned int download;
	unsigned int end;
	unsigned int start;
};

struct dionaeaKeys {
	unsigned int reference;
	char* connectionKey;
};

struct dionaeaSession {
	int startTime;
	int duration;
	int dlTime;
	unsigned int download;
	char* localIP;
	char* remoteIP;
	char* transport;
	unsigned int localPort;
	unsigned int remotePort;
	unsigned int incidentCount;
	unsigned int sessionCount;
	unsigned int sessionEndCount;
	char* incident;
};
