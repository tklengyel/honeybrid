#define OPEN 257
#define END 258
#define SEMICOLON 259
#define QUOTE 260
#define DOT 261
#define MODULE 262
#define FILTER 263
#define FRONTEND 264
#define BACKEND 265
#define LIMIT 266
#define CONFIGURATION 267
#define TARGET 268
#define NUMBER 269
#define WORD 270
#define EQ 271
#define EXPR 272
typedef union {
	int    number;
	char * string;
	GString * gstring;
	struct GHashTable * hash;
	struct target * target;
	struct addr * addr;
} YYSTYPE;
extern YYSTYPE yylval;
