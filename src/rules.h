#define OPEN 257
#define END 258
#define SEMICOLON 259
#define QUOTE 260
#define DOT 261
#define MODULE 262
#define FILTER 263
#define FRONTEND 264
#define BACKEND 265
#define BACKPICK 266
#define LIMIT 267
#define CONFIGURATION 268
#define TARGET 269
#define NUMBER 270
#define WORD 271
#define EQ 272
#define EXPR 273
typedef union {
	int    number;
	char * string;
	GString * gstring;
	struct GHashTable * hash;
	struct target * target;
	struct addr * addr;
} YYSTYPE;
extern YYSTYPE yylval;
