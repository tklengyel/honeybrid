#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20100610

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

#define YYPREFIX "yy"

#define YYPURE 0

#line 2 "rules.y"
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <pcap.h>
#include <dumbnet.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "tables.h"
#include "types.h"
#include "decision_engine.h"
#include <sys/stat.h>
#include <fcntl.h>

/*! Type of capture link */
#define LINKTYPE 1 	/*LINKTYPE_ETHERNET=1 \todo dynamically assign link type from nfqueue*/

enum { SOURCE = 1, DESTINATION, SOURCE_AND_DESTINATION, SOURCE_OR_DESTINATION };
extern int  yylineno;
extern char *yytext;
static void yyerror(const char *msg);

int yylex(void);

int yywrap() {
	/*! should return 0 if additional input has to be parsed, 1 if the end has been reached */
	return 1;
}

char* str_append(char * root, char * str);
char* int_append(char * root, int num);

#line 56 "rules.y"
typedef union {
	int    number;
	char * string;
	GString * gstring;
	struct GHashTable * hash;
	struct target * target;
	struct addr * addr;
} YYSTYPE;
#line 64 "rules.c"
/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

extern int YYPARSE_DECL();
extern int YYLEX_DECL();

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
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    0,    0,    0,    0,    5,    8,    8,    9,    9,    9,
    6,    1,    1,    1,    1,    7,    2,    2,    2,    2,
    2,    2,    4,    3,    3,    3,    3,    3,
};
static const short yylen[] = {                            2,
    0,    2,    2,    2,    4,    0,    3,    3,    3,    3,
    7,    0,    5,    5,    5,    4,    0,    6,    4,    7,
    7,    6,    1,    0,    2,    2,    2,    2,
};
static const short yydefred[] = {                         1,
    0,    0,    0,    0,    2,    3,    4,    0,    6,   17,
    0,    0,    0,    0,    5,    0,    0,   16,    0,    0,
    0,    0,   12,    0,    7,   24,   23,    0,    0,   24,
    0,   10,    8,    9,    0,   19,   24,   24,    0,   11,
    0,    0,   26,   25,   28,   27,    0,    0,    0,    0,
   18,    0,    0,   22,    0,    0,    0,   20,   21,   15,
   13,   14,
};
static const short yydgoto[] = {                          1,
   31,   13,   35,   28,    5,    6,    7,   12,   17,
};
static const short yysindex[] = {                         0,
 -261, -234, -220, -218,    0,    0,    0, -230,    0,    0,
 -213, -236, -222, -209,    0, -221, -210,    0, -208, -219,
 -219, -206,    0, -267,    0,    0,    0, -231, -205,    0,
 -235,    0,    0,    0, -260,    0,    0,    0, -256,    0,
 -215, -202,    0,    0,    0,    0, -252, -239, -201, -245,
    0, -200, -199,    0, -198, -197, -196,    0,    0,    0,
    0,    0,
};
static const short yyrindex[] = {                         0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,
};
static const short yygindex[] = {                         0,
    0,    0,    8,   30,    0,    0,    0,    0,    0,
};
#define YYTABLESIZE 63
static const short yytable[] = {                         42,
    2,   32,   33,   49,   34,    3,    4,   52,   43,   44,
   45,   46,   43,   44,   45,   46,   43,   44,   45,   46,
   53,   15,   40,   55,   56,    8,   57,   36,   37,   43,
   44,   45,   46,   16,   41,   18,    9,   39,   10,   11,
   19,   20,   21,   22,   47,   48,   14,   23,   25,   24,
   29,   26,   27,   30,   38,   50,   51,   54,   58,   59,
   60,   61,   62,
};
static const short yycheck[] = {                        260,
  262,  269,  270,  260,  272,  267,  268,  260,  269,  270,
  271,  272,  269,  270,  271,  272,  269,  270,  271,  272,
  260,  258,  258,  269,  270,  260,  272,  259,  260,  269,
  270,  271,  272,  270,  270,  258,  257,   30,  257,  270,
  263,  264,  265,  266,   37,   38,  260,  257,  259,  271,
   21,  260,  272,  260,  260,  271,  259,  259,  259,  259,
  259,  259,  259,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 1
#endif
#define YYMAXTOKEN 272
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"OPEN","END","SEMICOLON","QUOTE",
"DOT","MODULE","FILTER","FRONTEND","BACKEND","LIMIT","CONFIGURATION","TARGET",
"NUMBER","WORD","EQ","EXPR",
};
static const char *yyrule[] = {
"$accept : configuration",
"configuration :",
"configuration : configuration config",
"configuration : configuration module",
"configuration : configuration target",
"config : CONFIGURATION OPEN parameters END",
"parameters :",
"parameters : parameters parameter SEMICOLON",
"parameter : WORD EQ WORD",
"parameter : WORD EQ EXPR",
"parameter : WORD EQ NUMBER",
"module : MODULE QUOTE WORD QUOTE OPEN settings END",
"settings :",
"settings : settings WORD EQ WORD SEMICOLON",
"settings : settings WORD EQ EXPR SEMICOLON",
"settings : settings WORD EQ NUMBER SEMICOLON",
"target : TARGET OPEN rule END",
"rule :",
"rule : rule FILTER QUOTE equation QUOTE SEMICOLON",
"rule : rule FRONTEND honeynet SEMICOLON",
"rule : rule FRONTEND honeynet QUOTE equation QUOTE SEMICOLON",
"rule : rule BACKEND honeynet QUOTE equation QUOTE SEMICOLON",
"rule : rule LIMIT QUOTE equation QUOTE SEMICOLON",
"honeynet : EXPR",
"equation :",
"equation : equation WORD",
"equation : equation NUMBER",
"equation : equation EXPR",
"equation : equation EQ",

};
#endif
/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 318 "rules.y"

static void  yyerror(const char *msg) {
        errx(1,"line %d: %s at '%s'", yylineno, msg, yytext);
}

char* str_append(char * root, char * str) {
	g_printerr("\t##[1] root: %s, str: %s\n", root, str);
		char *tmp = (char *)calloc(strlen(root) + strlen(str), sizeof(char));
  		strcpy(tmp, root);
  		strncat(tmp, str, strlen(root) + strlen(str));
		root = realloc(root, strlen(root) + strlen(str));
		strcpy(root, tmp);
		free(tmp);
	g_printerr("\t##[1] root: %s\n\t=====================\n", root);
		return root;
}
char* int_append(char * root, int number) {
	g_printerr("\t##[1] root: %s, num: %d\n", root, number);
		char *num = malloc(128);
		sprintf(num, "%d", number);
		char *tmp = (char *)calloc(strlen(root) + strlen(num), sizeof(char));
  		strcpy(tmp, root);
  		strncat(tmp, num, strlen(root) + strlen(num));
		root = tmp;
		free(tmp);
		free(num);
	g_printerr("\t##[1] root: %s\n\t=====================\n", root);
		return root;
}

#line 283 "rules.c"

#if YYDEBUG
#include <stdio.h>		/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = data->s_mark - data->s_base;
    newss = (data->s_base != 0)
          ? (short *)realloc(data->s_base, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (data->l_base != 0)
          ? (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 2:
#line 84 "rules.y"
	{ 	g_printerr("Main config parsed\n"); }
break;
case 3:
#line 85 "rules.y"
	{	g_printerr("Module parsed\n"); }
break;
case 4:
#line 86 "rules.y"
	{	g_printerr("Target parsed\n"); }
break;
case 5:
#line 92 "rules.y"
	{ /* nothing to do */ }
break;
case 6:
#line 95 "rules.y"
	{ /* nothing to do */ }
break;
case 7:
#line 96 "rules.y"
	{ /* nothing to do */  }
break;
case 8:
#line 99 "rules.y"
	{
		g_hash_table_insert(config, yystack.l_mark[-2].string, yystack.l_mark[0].string);
		g_printerr("\t'%s' => '%s'\n", yystack.l_mark[-2].string, yystack.l_mark[0].string);
	}
break;
case 9:
#line 103 "rules.y"
	{
		g_hash_table_insert(config, yystack.l_mark[-2].string, yystack.l_mark[0].string);
                g_printerr("\t'%s' => '%s'\n", yystack.l_mark[-2].string, yystack.l_mark[0].string);
	}
break;
case 10:
#line 107 "rules.y"
	{
		/*char *s = malloc(sizeof($3));*/
		char *s = malloc(128);
		snprintf(s, 128, "%d",yystack.l_mark[0].number);
		g_hash_table_insert(config, yystack.l_mark[-2].string, s);
		g_printerr("\t'%s' => '%d'\n", yystack.l_mark[-2].string, yystack.l_mark[0].number);
        }
break;
case 11:
#line 120 "rules.y"
	{
		g_hash_table_insert(module, yystack.l_mark[-4].string, yystack.l_mark[-1].hash);
		g_printerr("\tmodule '%s' defined with %d parameters\n", yystack.l_mark[-4].string, g_hash_table_size((GHashTable *)yystack.l_mark[-1].hash));
		if (NULL == g_hash_table_lookup((GHashTable *)yystack.l_mark[-1].hash, "function")) {
			errx(1, "%s: Fatal error: missing parameter 'function' in module '%s'\n", __func__, yystack.l_mark[-4].string);
		} else {
			/*g_printerr("\tModule function defined as '%s'\n", (char *)g_hash_table_lookup((GHashTable *)$6, "function"));*/
			/*//g_hash_table_replace((GHashTable *)$6, "function", get_module((char *)g_hash_table_lookup((GHashTable *)$6, "function")));*/
			g_hash_table_insert((GHashTable *)yystack.l_mark[-1].hash, "function_pointer", get_module((char *)g_hash_table_lookup((GHashTable *)yystack.l_mark[-1].hash, "function")));
			/*g_printerr("\tModule function defined at address %p\n", g_hash_table_lookup((GHashTable *)$6, "function"));*/
		}
		
		gchar *backup_file;
		if (NULL != (backup_file = (char *)g_hash_table_lookup((GHashTable *)yystack.l_mark[-1].hash, "backup_file"))) {
			int backup_fd;
			GError *error = NULL;
			GKeyFile *backup = NULL;
			backup = g_key_file_new();
			g_key_file_set_list_separator(backup, '\t');
			/*! We store a pointer to GKeyFile object in the module hash table */
			g_hash_table_insert((GHashTable *)yystack.l_mark[-1].hash, "backup", backup);
			g_printerr("\t%s: New GKeyFile %p created\n", __func__, backup);
			/*! We then check if the file exists. Otherwise we create it */
			if (FALSE == g_file_test(backup_file, G_FILE_TEST_IS_REGULAR)) {
				if (-1 == (backup_fd = g_open(backup_file, O_WRONLY | O_CREAT | O_TRUNC, NULL))) {
					errx(1, "%s: Fatal error, can't create backup file for module", __func__);
				} else {
					/*g_hash_table_insert((GHashTable *)$6, "backup_fd", &backup_fd);*/
					close(backup_fd);
				}
			} else {
				/*! If the file exists, we try to load it into memory */
				/*! \todo free all these structures, and close file descriptor when exiting */
				if (FALSE == g_key_file_load_from_file(
					g_hash_table_lookup((GHashTable *)yystack.l_mark[-1].hash, "backup"),
					backup_file,
					G_KEY_FILE_KEEP_COMMENTS,
					&error)) {
					g_printerr("\t%s: can't load backup file for module: %s\n", __func__, error->message);
				}
			}
			/*g_free(backup_file);*/
		}
	}
break;
case 12:
#line 166 "rules.y"
	{ 
		if (NULL == (yyval.hash = (struct GHashTable *)g_hash_table_new(g_str_hash, g_str_equal)))
	                errx(1, "%s: Fatal error while creating module hash table.\n", __func__);
	}
break;
case 13:
#line 170 "rules.y"
	{
		if (g_strcmp0(yystack.l_mark[-3].string, "function") == 0) {
			/*! We store a pointer to the module function in the module hash table 
			    If the module function isn't defined in get_module(), the application will exit and display an error message */
                        g_hash_table_insert((GHashTable *)yyval.hash, "function", yystack.l_mark[-1].string);
		}
		if (g_strcmp0(yystack.l_mark[-3].string, "backup") == 0) {
			GString *tmp = g_string_new(yystack.l_mark[-1].string);
                        g_hash_table_insert((GHashTable *)yyval.hash, "backup_file", g_string_free(tmp, FALSE));
		}
		g_hash_table_insert((GHashTable *)yyval.hash, yystack.l_mark[-3].string, yystack.l_mark[-1].string);
                g_printerr("\t'%s' => '%s'\n", yystack.l_mark[-3].string, yystack.l_mark[-1].string);
	}
break;
case 14:
#line 183 "rules.y"
	{
		if (g_strcmp0(yystack.l_mark[-3].string, "function") == 0) {
			/*! We store a pointer to the module function in the module hash table 
			    If the module function isn't defined in get_module(), the application will exit and display an error message */
                        g_hash_table_insert((GHashTable *)yyval.hash, "function", yystack.l_mark[-1].string);
		}
		if (g_strcmp0(yystack.l_mark[-3].string, "backup") == 0) {
			GString *tmp = g_string_new(yystack.l_mark[-1].string);
                        g_hash_table_insert((GHashTable *)yyval.hash, "backup_file", g_string_free(tmp, FALSE));
		}
		g_hash_table_insert((GHashTable *)yyval.hash, yystack.l_mark[-3].string, yystack.l_mark[-1].string);
                g_printerr("\t'%s' => '%s'\n", yystack.l_mark[-3].string, yystack.l_mark[-1].string);
	}
break;
case 15:
#line 196 "rules.y"
	{
		char *s = malloc(sizeof(double));
                sprintf(s, "%d",yystack.l_mark[-1].number);
                g_hash_table_insert((GHashTable *)yyval.hash, yystack.l_mark[-3].string, s);
                g_printerr("\t'%s' => '%d'\n", yystack.l_mark[-3].string, yystack.l_mark[-1].number);
	}
break;
case 16:
#line 211 "rules.y"
	{
		/*
		if (pcap_compile_nopcap(1500, LINKTYPE, $6->filter, $3, 1, 0) < 0) {
			g_printerr("PCAP ERROR: '%s'\n", $3);
                	yyerror("bad pcap filter");
		}
		*/
		g_printerr("\tGoing to add new element to target array...\n");
		g_ptr_array_add(targets, yystack.l_mark[-1].target);
		g_printerr("\t...done\n");
		g_printerr("\tAdded a new target with the following values:\n\tfront_handler: %s\n\tfront_rule: %s\n\tback_handler: %s\n\tback_rule: %s\n\tlimit: %s\n",
				/*addr_ntoa($3->front_handler), "-", //$3->front_rule->module_name->str,*/
				/*addr_ntoa($3->back_handler), "-"); //$3->back_rule->module_name->str);*/
				addr_ntoa(yystack.l_mark[-1].target->front_handler),(yystack.l_mark[-1].target->front_rule == NULL) ? "(null)" : yystack.l_mark[-1].target->front_rule->module_name->str,
				addr_ntoa(yystack.l_mark[-1].target->back_handler), (yystack.l_mark[-1].target->back_rule  == NULL) ? "(null)" : yystack.l_mark[-1].target->back_rule->module_name->str,
				(yystack.l_mark[-1].target->control_rule  == NULL) ? "(null)" : yystack.l_mark[-1].target->control_rule->module_name->str);
	}
break;
case 17:
#line 230 "rules.y"
	{
		g_printerr("\tAllocating memory for new structure 'target'\n");
		yyval.target = malloc(sizeof(struct target));
		yyval.target->front_handler = (struct addr *)g_malloc0(sizeof(struct addr));
		yyval.target->back_handler = (struct addr *)g_malloc0(sizeof(struct addr));
		yyval.target->front_rule = NULL;
		yyval.target->back_rule = NULL;
		yyval.target->control_rule = NULL;

	}
break;
case 18:
#line 240 "rules.y"
	{
		/*g_printerr("Read pcap filter: '%s'\n", $4);*/
		/*g_printerr("Read pcap filter: '%s'\n", g_string_free($4, FALSE));*/
		/*if (pcap_compile_nopcap(1500, LINKTYPE, $$->filter, $4->str, 1, 0) < 0) {*/
		yyval.target->filter = malloc(sizeof(struct bpf_program));
		if (pcap_compile_nopcap(1500, LINKTYPE, yyval.target->filter, yystack.l_mark[-2].gstring->str, 1, 0) < 0) {
			g_printerr("\tPCAP ERROR: '%s'\n", yystack.l_mark[-2].gstring->str);
                	yyerror("\tIncorrect pcap filter");
		}
		g_printerr("\tPCAP filter compiled:%s\n", yystack.l_mark[-2].gstring->str);	
		g_string_free(yystack.l_mark[-2].gstring, TRUE);
	}
break;
case 19:
#line 252 "rules.y"
	{
		yyval.target->front_handler = yystack.l_mark[-1].addr;
		g_printerr("\tIP %s (%d) copied to handler\n", addr_ntoa(yystack.l_mark[-1].addr), yystack.l_mark[-1].addr->addr_ip);
		g_printerr("\tResult IP %s (%d)\n", addr_ntoa(yyval.target->front_handler), yyval.target->front_handler->addr_ip);
		yyval.target->front_rule = NULL;
	}
break;
case 20:
#line 258 "rules.y"
	{
		yyval.target->front_handler = yystack.l_mark[-4].addr;
		g_printerr("\tIP %s (%d) copied to handler\n", addr_ntoa(yystack.l_mark[-4].addr), yystack.l_mark[-4].addr->addr_ip);
		yyval.target->front_rule = DE_create_tree(yystack.l_mark[-2].gstring->str);
		g_string_free(yystack.l_mark[-2].gstring, TRUE);
	}
break;
case 21:
#line 264 "rules.y"
	{
		yyval.target->back_handler = yystack.l_mark[-4].addr;
		g_printerr("\tIP %s (%d) copied to handler\n", addr_ntoa(yystack.l_mark[-4].addr), yystack.l_mark[-4].addr->addr_ip);
		yyval.target->back_rule = DE_create_tree(yystack.l_mark[-2].gstring->str);
		g_string_free(yystack.l_mark[-2].gstring, TRUE);
	}
break;
case 22:
#line 270 "rules.y"
	{
		yyval.target->control_rule = DE_create_tree(yystack.l_mark[-2].gstring->str);
		g_string_free(yystack.l_mark[-2].gstring, TRUE);
	}
break;
case 23:
#line 276 "rules.y"
	{ 
		if (addr_pton(yystack.l_mark[0].string, yyval.addr) < 0)
                        yyerror("\tIllegal IP address");
		else 
			g_printerr("\tIP %s (%d) added as honeypot\n", addr_ntoa(yyval.addr), yyval.addr->addr_ip);
                /*g_free($1);*/
	}
break;
case 24:
#line 286 "rules.y"
	{ 
		/*$$ = malloc(sizeof(char));*/
		/*snprintf($$, 1, " ");*/
		yyval.gstring = g_string_new("");
	}
break;
case 25:
#line 291 "rules.y"
	{
		if (yyval.gstring->len > 0) { g_string_append_printf(yyval.gstring, " "); }
		yyval.gstring = g_string_append(yyval.gstring, yystack.l_mark[0].string);
		/*$$ = str_append($$, " ");*/
		/*$$ = str_append($$, $2);*/
	 }
break;
case 26:
#line 297 "rules.y"
	{ 
		if (yyval.gstring->len > 0) { g_string_append_printf(yyval.gstring, " "); }
		g_string_append_printf(yyval.gstring, "%d", yystack.l_mark[0].number);
		/*$$ = str_append($$, " ");*/
		/*$$ = int_append($$, $2);*/
	 }
break;
case 27:
#line 303 "rules.y"
	{ 
		if (yyval.gstring->len > 0) { g_string_append_printf(yyval.gstring, " "); }
		yyval.gstring = g_string_append(yyval.gstring, yystack.l_mark[0].string);
		/*$$ = str_append($$, " ");*/
		/*$$ = str_append($$, $2);*/
	 }
break;
case 28:
#line 309 "rules.y"
	{ 
		if (yyval.gstring->len > 0) { g_string_append_printf(yyval.gstring, " "); }
		yyval.gstring = g_string_append(yyval.gstring, yystack.l_mark[0].string);
		/*$$ = str_append($$, " ");*/
		/*$$ = str_append($$, $2);*/
	 }
break;
#line 772 "rules.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
