// This class has been generated automatically
// from an SABNF grammar by Java APG, Verision 1.1.0.
// Copyright (c) 2021 Lowell D. Thomas, all rights reserved.
// Licensed under the 2-Clause BSD License.

package com.moonstoneid.siwe.grammar;

import apg.Grammar;
import java.io.PrintStream;

public class SiweGrammar extends Grammar{

    // public API
    public static Grammar getInstance(){
        if(factoryInstance == null){
            factoryInstance = new SiweGrammar(getRules(), getUdts(), getOpcodes());
        }
        return factoryInstance;
    }

    // rule name enum
    public static int ruleCount = 81;
    public enum RuleNames{
        ADDRESS("address", 7, 66, 4),
        ALPHA("ALPHA", 77, 452, 3),
        AUTHORITY("authority", 22, 135, 8),
        AUTHORITY_D("authority-d", 52, 332, 10),
        CHAIN_ID("chain-id", 16, 98, 2),
        DATE_FULLYEAR("date-fullyear", 64, 405, 2),
        DATE_MDAY("date-mday", 66, 409, 2),
        DATE_MONTH("date-month", 65, 407, 2),
        DATE_TIME("date-time", 76, 448, 4),
        DCOLON("dcolon", 34, 221, 19),
        DEC_DIGIT("dec-digit", 41, 267, 1),
        DEC_OCTET("dec-octet", 40, 265, 2),
        DIGIT("DIGIT", 79, 456, 1),
        DOMAIN("domain", 6, 65, 1),
        EMPTY_STATEMENT("empty-statement", 9, 84, 4),
        EX_TITLE("ex-title", 1, 51, 1),
        EXPIRATION_TIME("expiration-time", 13, 94, 1),
        FRAGMENT("fragment", 46, 289, 5),
        FRAGMENT_R("fragment-r", 51, 327, 5),
        FULL_DATE("full-date", 74, 439, 6),
        FULL_TIME("full-time", 75, 445, 3),
        H16("h16", 35, 240, 2),
        H16C("h16c", 36, 242, 4),
        H16CN("h16cn", 38, 251, 6),
        H16N("h16n", 37, 246, 5),
        HEXDIG("HEXDIG", 80, 457, 4),
        HIER_PART("hier-part", 20, 119, 8),
        HIER_PART_R("hier-part-r", 48, 306, 8),
        HOST("host", 29, 179, 7),
        HOST_D("host-d", 54, 355, 7),
        IP_LITERAL("IP-literal", 30, 186, 6),
        IPV4ADDRESS("IPv4address", 39, 257, 8),
        IPV6ADDRESS("IPv6address", 32, 209, 3),
        IPVFUTURE("IPvFuture", 31, 192, 17),
        ISSUED_AT("issued-at", 12, 93, 1),
        LF("LF", 78, 455, 1),
        NB_TITLE("nb-title", 2, 52, 1),
        NODCOLON("nodcolon", 33, 212, 9),
        NONCE("nonce", 11, 89, 4),
        NOT_BEFORE("not-before", 14, 95, 1),
        OSCHEME("oscheme", 5, 55, 10),
        PARTIAL_TIME("partial-time", 73, 431, 8),
        PATH_ABEMPTY("path-abempty", 23, 143, 4),
        PATH_ABEMPTY_R("path-abempty-r", 56, 364, 4),
        PATH_ABSOLUTE("path-absolute", 24, 147, 9),
        PATH_ABSOLUTE_R("path-absolute-r", 57, 368, 9),
        PATH_EMPTY("path-empty", 26, 162, 1),
        PATH_EMPTY_R("path-empty-r", 59, 383, 1),
        PATH_ROOTLESS("path-rootless", 25, 156, 6),
        PATH_ROOTLESS_R("path-rootless-r", 58, 377, 6),
        PCHAR("pchar", 62, 388, 13),
        PCT_ENCODED("pct-encoded", 63, 401, 4),
        PORT("port", 44, 282, 2),
        PORT_D("port-d", 55, 362, 2),
        QUERY("query", 45, 284, 5),
        QUERY_R("query-r", 50, 322, 5),
        RE_TITLE("re-title", 4, 54, 1),
        REG_NAME("reg-name", 42, 268, 2),
        REG_NAME_CHAR("reg-name-char", 43, 270, 12),
        REQUEST_ID("request-id", 15, 96, 2),
        RESOURCE("resource", 18, 104, 3),
        RESOURCES("resources", 17, 100, 4),
        RI_TITLE("ri-title", 3, 53, 1),
        SCHEME("scheme", 21, 127, 8),
        SCHEME_R("scheme-r", 49, 314, 8),
        SEGMENT("segment", 60, 384, 2),
        SEGMENT_NZ("segment-nz", 61, 386, 2),
        SIGN_IN_WITH_ETHEREUM("sign-in-with-ethereum", 0, 0, 51),
        STATEMENT("statement", 8, 70, 14),
        TIME_HOUR("time-hour", 67, 411, 2),
        TIME_MINUTE("time-minute", 68, 413, 2),
        TIME_NUMOFFSET("time-numoffset", 71, 421, 7),
        TIME_OFFSET("time-offset", 72, 428, 3),
        TIME_SECFRAC("time-secfrac", 70, 417, 4),
        TIME_SECOND("time-second", 69, 415, 2),
        URI("URI", 19, 107, 12),
        URI_R("URI-r", 47, 294, 12),
        USERINFO("userinfo", 28, 166, 13),
        USERINFO_AT("userinfo-at", 27, 163, 3),
        USERINFO_D("userinfo-d", 53, 342, 13),
        VERSION("version", 10, 88, 1);
        private String name;
        private int id;
        private int offset;
        private int count;
        RuleNames(String string, int id, int offset, int count){
            this.name = string;
            this.id = id;
            this.offset = offset;
            this.count = count;
        }
        public  String ruleName(){return name;}
        public  String ruleEnumName(){return name();}
        public  int    ruleID(){return id;}
        private int    opcodeOffset(){return offset;}
        private int    opcodeCount(){return count;}
    }

    // UDT name enum
    public static int udtCount = 0;
    public enum UdtNames{
    }

    // private
    private static SiweGrammar factoryInstance = null;
    private SiweGrammar(Rule[] rules, Udt[] udts, Opcode[] opcodes){
        super(rules, udts, opcodes);
    }

    private static Rule[] getRules(){
        Rule[] rules = new Rule[81];
        for(RuleNames r : RuleNames.values()){
            rules[r.ruleID()] = getRule(r.ruleID(), r.ruleName(), r.opcodeOffset(), r.opcodeCount());
        }
        return rules;
    }

    private static Udt[] getUdts(){
        Udt[] udts = new Udt[0];
        return udts;
    }

    // opcodes
    private static Opcode[] getOpcodes(){
        Opcode[] op = new Opcode[461];
        addOpcodes00(op);
        return op;
    }

    private static void addOpcodes00(Opcode[] op){
        {int[] a = {1,2,3,4,5,6,7,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,36,41,46}; op[0] = getOpcodeCat(a);}
        op[1] = getOpcodeRnm(5, 55); // oscheme
        op[2] = getOpcodeRnm(6, 65); // domain
        {char[] a = {32,119,97,110,116,115,32,121,111,117,32,116,111,32,115,105,103,110,32,105,110,32,119,105,116,104,32,121,111,117,114,32,69,116,104,101,114,101,117,109,32,97,99,99,111,117,110,116,58}; op[3] = getOpcodeTbs(a);}
        op[4] = getOpcodeRnm(78, 455); // LF
        op[5] = getOpcodeRnm(7, 66); // address
        op[6] = getOpcodeRnm(78, 455); // LF
        {int[] a = {8,13,14}; op[7] = getOpcodeAlt(a);}
        {int[] a = {9,10,11,12}; op[8] = getOpcodeCat(a);}
        op[9] = getOpcodeRnm(78, 455); // LF
        op[10] = getOpcodeRnm(8, 70); // statement
        op[11] = getOpcodeRnm(78, 455); // LF
        op[12] = getOpcodeRnm(78, 455); // LF
        op[13] = getOpcodeRnm(9, 84); // empty-statement
        {int[] a = {15,16}; op[14] = getOpcodeCat(a);}
        op[15] = getOpcodeRnm(78, 455); // LF
        op[16] = getOpcodeRnm(78, 455); // LF
        {char[] a = {85,82,73,58,32}; op[17] = getOpcodeTbs(a);}
        op[18] = getOpcodeRnm(19, 107); // URI
        op[19] = getOpcodeRnm(78, 455); // LF
        {char[] a = {86,101,114,115,105,111,110,58,32}; op[20] = getOpcodeTbs(a);}
        op[21] = getOpcodeRnm(10, 88); // version
        op[22] = getOpcodeRnm(78, 455); // LF
        {char[] a = {67,104,97,105,110,32,73,68,58,32}; op[23] = getOpcodeTbs(a);}
        op[24] = getOpcodeRnm(16, 98); // chain-id
        op[25] = getOpcodeRnm(78, 455); // LF
        {char[] a = {78,111,110,99,101,58,32}; op[26] = getOpcodeTbs(a);}
        op[27] = getOpcodeRnm(11, 89); // nonce
        op[28] = getOpcodeRnm(78, 455); // LF
        {char[] a = {73,115,115,117,101,100,32,65,116,58,32}; op[29] = getOpcodeTbs(a);}
        op[30] = getOpcodeRnm(12, 93); // issued-at
        op[31] = getOpcodeRep((char)0, (char)1, 32);
        {int[] a = {33,34,35}; op[32] = getOpcodeCat(a);}
        op[33] = getOpcodeRnm(78, 455); // LF
        op[34] = getOpcodeRnm(1, 51); // ex-title
        op[35] = getOpcodeRnm(13, 94); // expiration-time
        op[36] = getOpcodeRep((char)0, (char)1, 37);
        {int[] a = {38,39,40}; op[37] = getOpcodeCat(a);}
        op[38] = getOpcodeRnm(78, 455); // LF
        op[39] = getOpcodeRnm(2, 52); // nb-title
        op[40] = getOpcodeRnm(14, 95); // not-before
        op[41] = getOpcodeRep((char)0, (char)1, 42);
        {int[] a = {43,44,45}; op[42] = getOpcodeCat(a);}
        op[43] = getOpcodeRnm(78, 455); // LF
        op[44] = getOpcodeRnm(3, 53); // ri-title
        op[45] = getOpcodeRnm(15, 96); // request-id
        op[46] = getOpcodeRep((char)0, (char)1, 47);
        {int[] a = {48,49,50}; op[47] = getOpcodeCat(a);}
        op[48] = getOpcodeRnm(78, 455); // LF
        op[49] = getOpcodeRnm(4, 54); // re-title
        op[50] = getOpcodeRnm(17, 100); // resources
        {char[] a = {69,120,112,105,114,97,116,105,111,110,32,84,105,109,101,58,32}; op[51] = getOpcodeTbs(a);}
        {char[] a = {78,111,116,32,66,101,102,111,114,101,58,32}; op[52] = getOpcodeTbs(a);}
        {char[] a = {82,101,113,117,101,115,116,32,73,68,58,32}; op[53] = getOpcodeTbs(a);}
        {char[] a = {82,101,115,111,117,114,99,101,115,58}; op[54] = getOpcodeTbs(a);}
        op[55] = getOpcodeRep((char)0, (char)1, 56);
        {int[] a = {57,58,64}; op[56] = getOpcodeCat(a);}
        op[57] = getOpcodeRnm(77, 452); // ALPHA
        op[58] = getOpcodeRep((char)0, Character.MAX_VALUE, 59);
        {int[] a = {60,61,62,63}; op[59] = getOpcodeAlt(a);}
        op[60] = getOpcodeRnm(77, 452); // ALPHA
        op[61] = getOpcodeRnm(79, 456); // DIGIT
        {char[] a = {43}; op[62] = getOpcodeTbs(a);}
        op[63] = getOpcodeTrg((char)45, (char)46);
        {char[] a = {58,47,47}; op[64] = getOpcodeTls(a);}
        op[65] = getOpcodeRnm(52, 332); // authority-d
        {int[] a = {67,68}; op[66] = getOpcodeCat(a);}
        {char[] a = {48,120}; op[67] = getOpcodeTls(a);}
        op[68] = getOpcodeRep((char)40, (char)40, 69);
        op[69] = getOpcodeRnm(80, 457); // HEXDIG
        op[70] = getOpcodeRep((char)1, Character.MAX_VALUE, 71);
        {int[] a = {72,73,74,75,76,77,78,79,80,81,82,83}; op[71] = getOpcodeAlt(a);}
        op[72] = getOpcodeTrg((char)97, (char)122);
        op[73] = getOpcodeTrg((char)65, (char)90);
        op[74] = getOpcodeTrg((char)48, (char)57);
        op[75] = getOpcodeTrg((char)32, (char)33);
        op[76] = getOpcodeTrg((char)35, (char)36);
        op[77] = getOpcodeTrg((char)38, (char)59);
        {char[] a = {61}; op[78] = getOpcodeTbs(a);}
        op[79] = getOpcodeTrg((char)63, (char)64);
        {char[] a = {91}; op[80] = getOpcodeTbs(a);}
        {char[] a = {93}; op[81] = getOpcodeTbs(a);}
        {char[] a = {95}; op[82] = getOpcodeTbs(a);}
        {char[] a = {126}; op[83] = getOpcodeTbs(a);}
        {int[] a = {85,86,87}; op[84] = getOpcodeCat(a);}
        op[85] = getOpcodeRnm(78, 455); // LF
        op[86] = getOpcodeRnm(78, 455); // LF
        op[87] = getOpcodeRnm(78, 455); // LF
        {char[] a = {49}; op[88] = getOpcodeTls(a);}
        op[89] = getOpcodeRep((char)8, Character.MAX_VALUE, 90);
        {int[] a = {91,92}; op[90] = getOpcodeAlt(a);}
        op[91] = getOpcodeRnm(77, 452); // ALPHA
        op[92] = getOpcodeRnm(79, 456); // DIGIT
        op[93] = getOpcodeRnm(76, 448); // date-time
        op[94] = getOpcodeRnm(76, 448); // date-time
        op[95] = getOpcodeRnm(76, 448); // date-time
        op[96] = getOpcodeRep((char)0, Character.MAX_VALUE, 97);
        op[97] = getOpcodeRnm(62, 388); // pchar
        op[98] = getOpcodeRep((char)1, Character.MAX_VALUE, 99);
        op[99] = getOpcodeRnm(79, 456); // DIGIT
        op[100] = getOpcodeRep((char)0, Character.MAX_VALUE, 101);
        {int[] a = {102,103}; op[101] = getOpcodeCat(a);}
        op[102] = getOpcodeRnm(78, 455); // LF
        op[103] = getOpcodeRnm(18, 104); // resource
        {int[] a = {105,106}; op[104] = getOpcodeCat(a);}
        {char[] a = {45,32}; op[105] = getOpcodeTls(a);}
        op[106] = getOpcodeRnm(47, 294); // URI-r
        {int[] a = {108,109,110,111,115}; op[107] = getOpcodeCat(a);}
        op[108] = getOpcodeRnm(21, 127); // scheme
        {char[] a = {58}; op[109] = getOpcodeTls(a);}
        op[110] = getOpcodeRnm(20, 119); // hier-part
        op[111] = getOpcodeRep((char)0, (char)1, 112);
        {int[] a = {113,114}; op[112] = getOpcodeCat(a);}
        {char[] a = {63}; op[113] = getOpcodeTls(a);}
        op[114] = getOpcodeRnm(45, 284); // query
        op[115] = getOpcodeRep((char)0, (char)1, 116);
        {int[] a = {117,118}; op[116] = getOpcodeCat(a);}
        {char[] a = {35}; op[117] = getOpcodeTls(a);}
        op[118] = getOpcodeRnm(46, 289); // fragment
        {int[] a = {120,124,125,126}; op[119] = getOpcodeAlt(a);}
        {int[] a = {121,122,123}; op[120] = getOpcodeCat(a);}
        {char[] a = {47,47}; op[121] = getOpcodeTls(a);}
        op[122] = getOpcodeRnm(22, 135); // authority
        op[123] = getOpcodeRnm(23, 143); // path-abempty
        op[124] = getOpcodeRnm(24, 147); // path-absolute
        op[125] = getOpcodeRnm(25, 156); // path-rootless
        op[126] = getOpcodeRnm(26, 162); // path-empty
        {int[] a = {128,129}; op[127] = getOpcodeCat(a);}
        op[128] = getOpcodeRnm(77, 452); // ALPHA
        op[129] = getOpcodeRep((char)0, Character.MAX_VALUE, 130);
        {int[] a = {131,132,133,134}; op[130] = getOpcodeAlt(a);}
        op[131] = getOpcodeRnm(77, 452); // ALPHA
        op[132] = getOpcodeRnm(79, 456); // DIGIT
        {char[] a = {43}; op[133] = getOpcodeTbs(a);}
        op[134] = getOpcodeTrg((char)45, (char)46);
        {int[] a = {136,138,139}; op[135] = getOpcodeCat(a);}
        op[136] = getOpcodeRep((char)0, (char)1, 137);
        op[137] = getOpcodeRnm(27, 163); // userinfo-at
        op[138] = getOpcodeRnm(29, 179); // host
        op[139] = getOpcodeRep((char)0, (char)1, 140);
        {int[] a = {141,142}; op[140] = getOpcodeCat(a);}
        {char[] a = {58}; op[141] = getOpcodeTls(a);}
        op[142] = getOpcodeRnm(44, 282); // port
        op[143] = getOpcodeRep((char)0, Character.MAX_VALUE, 144);
        {int[] a = {145,146}; op[144] = getOpcodeCat(a);}
        {char[] a = {47}; op[145] = getOpcodeTls(a);}
        op[146] = getOpcodeRnm(60, 384); // segment
        {int[] a = {148,149}; op[147] = getOpcodeCat(a);}
        {char[] a = {47}; op[148] = getOpcodeTls(a);}
        op[149] = getOpcodeRep((char)0, (char)1, 150);
        {int[] a = {151,152}; op[150] = getOpcodeCat(a);}
        op[151] = getOpcodeRnm(61, 386); // segment-nz
        op[152] = getOpcodeRep((char)0, Character.MAX_VALUE, 153);
        {int[] a = {154,155}; op[153] = getOpcodeCat(a);}
        {char[] a = {47}; op[154] = getOpcodeTls(a);}
        op[155] = getOpcodeRnm(60, 384); // segment
        {int[] a = {157,158}; op[156] = getOpcodeCat(a);}
        op[157] = getOpcodeRnm(61, 386); // segment-nz
        op[158] = getOpcodeRep((char)0, Character.MAX_VALUE, 159);
        {int[] a = {160,161}; op[159] = getOpcodeCat(a);}
        {char[] a = {47}; op[160] = getOpcodeTls(a);}
        op[161] = getOpcodeRnm(60, 384); // segment
        {char[] a = {}; op[162] = getOpcodeTls(a);}
        {int[] a = {164,165}; op[163] = getOpcodeCat(a);}
        op[164] = getOpcodeRnm(28, 166); // userinfo
        {char[] a = {64}; op[165] = getOpcodeTbs(a);}
        op[166] = getOpcodeRep((char)0, Character.MAX_VALUE, 167);
        {int[] a = {168,169,170,171,172,173,174,175,176,177,178}; op[167] = getOpcodeAlt(a);}
        op[168] = getOpcodeTrg((char)97, (char)122);
        op[169] = getOpcodeTrg((char)65, (char)90);
        op[170] = getOpcodeTrg((char)48, (char)57);
        op[171] = getOpcodeRnm(63, 401); // pct-encoded
        {char[] a = {33}; op[172] = getOpcodeTbs(a);}
        {char[] a = {36}; op[173] = getOpcodeTbs(a);}
        op[174] = getOpcodeTrg((char)38, (char)46);
        op[175] = getOpcodeTrg((char)58, (char)59);
        {char[] a = {61}; op[176] = getOpcodeTbs(a);}
        {char[] a = {95}; op[177] = getOpcodeTbs(a);}
        {char[] a = {126}; op[178] = getOpcodeTbs(a);}
        {int[] a = {180,181,185}; op[179] = getOpcodeAlt(a);}
        op[180] = getOpcodeRnm(30, 186); // IP-literal
        {int[] a = {182,183}; op[181] = getOpcodeCat(a);}
        op[182] = getOpcodeRnm(39, 257); // IPv4address
        op[183] = getOpcodeNot(184);
        op[184] = getOpcodeRnm(43, 270); // reg-name-char
        op[185] = getOpcodeRnm(42, 268); // reg-name
        {int[] a = {187,188,191}; op[186] = getOpcodeCat(a);}
        {char[] a = {91}; op[187] = getOpcodeTls(a);}
        {int[] a = {189,190}; op[188] = getOpcodeAlt(a);}
        op[189] = getOpcodeRnm(32, 209); // IPv6address
        op[190] = getOpcodeRnm(31, 192); // IPvFuture
        {char[] a = {93}; op[191] = getOpcodeTls(a);}
        {int[] a = {193,194,196,197}; op[192] = getOpcodeCat(a);}
        {char[] a = {118}; op[193] = getOpcodeTls(a);}
        op[194] = getOpcodeRep((char)1, Character.MAX_VALUE, 195);
        op[195] = getOpcodeRnm(80, 457); // HEXDIG
        {char[] a = {46}; op[196] = getOpcodeTls(a);}
        op[197] = getOpcodeRep((char)1, Character.MAX_VALUE, 198);
        {int[] a = {199,200,201,202,203,204,205,206,207,208}; op[198] = getOpcodeAlt(a);}
        op[199] = getOpcodeTrg((char)97, (char)122);
        op[200] = getOpcodeTrg((char)65, (char)90);
        op[201] = getOpcodeTrg((char)48, (char)57);
        {char[] a = {33}; op[202] = getOpcodeTbs(a);}
        {char[] a = {36}; op[203] = getOpcodeTbs(a);}
        op[204] = getOpcodeTrg((char)38, (char)46);
        op[205] = getOpcodeTrg((char)58, (char)59);
        {char[] a = {61}; op[206] = getOpcodeTbs(a);}
        {char[] a = {95}; op[207] = getOpcodeTbs(a);}
        {char[] a = {126}; op[208] = getOpcodeTbs(a);}
        {int[] a = {210,211}; op[209] = getOpcodeAlt(a);}
        op[210] = getOpcodeRnm(33, 212); // nodcolon
        op[211] = getOpcodeRnm(34, 221); // dcolon
        {int[] a = {213,217}; op[212] = getOpcodeCat(a);}
        {int[] a = {214,215}; op[213] = getOpcodeCat(a);}
        op[214] = getOpcodeRnm(37, 246); // h16n
        op[215] = getOpcodeRep((char)0, Character.MAX_VALUE, 216);
        op[216] = getOpcodeRnm(38, 251); // h16cn
        op[217] = getOpcodeRep((char)0, (char)1, 218);
        {int[] a = {219,220}; op[218] = getOpcodeCat(a);}
        {char[] a = {58}; op[219] = getOpcodeTbs(a);}
        op[220] = getOpcodeRnm(39, 257); // IPv4address
        {int[] a = {222,227,228}; op[221] = getOpcodeCat(a);}
        op[222] = getOpcodeRep((char)0, (char)1, 223);
        {int[] a = {224,225}; op[223] = getOpcodeCat(a);}
        op[224] = getOpcodeRnm(35, 240); // h16
        op[225] = getOpcodeRep((char)0, Character.MAX_VALUE, 226);
        op[226] = getOpcodeRnm(36, 242); // h16c
        {char[] a = {58,58}; op[227] = getOpcodeTbs(a);}
        {int[] a = {229,238}; op[228] = getOpcodeAlt(a);}
        {int[] a = {230,234}; op[229] = getOpcodeCat(a);}
        {int[] a = {231,232}; op[230] = getOpcodeCat(a);}
        op[231] = getOpcodeRnm(37, 246); // h16n
        op[232] = getOpcodeRep((char)0, Character.MAX_VALUE, 233);
        op[233] = getOpcodeRnm(38, 251); // h16cn
        op[234] = getOpcodeRep((char)0, (char)1, 235);
        {int[] a = {236,237}; op[235] = getOpcodeCat(a);}
        {char[] a = {58}; op[236] = getOpcodeTbs(a);}
        op[237] = getOpcodeRnm(39, 257); // IPv4address
        op[238] = getOpcodeRep((char)0, (char)1, 239);
        op[239] = getOpcodeRnm(39, 257); // IPv4address
        op[240] = getOpcodeRep((char)1, (char)4, 241);
        op[241] = getOpcodeRnm(80, 457); // HEXDIG
        {int[] a = {243,244}; op[242] = getOpcodeCat(a);}
        {char[] a = {58}; op[243] = getOpcodeTbs(a);}
        op[244] = getOpcodeRep((char)1, (char)4, 245);
        op[245] = getOpcodeRnm(80, 457); // HEXDIG
        {int[] a = {247,249}; op[246] = getOpcodeCat(a);}
        op[247] = getOpcodeRep((char)1, (char)4, 248);
        op[248] = getOpcodeRnm(80, 457); // HEXDIG
        op[249] = getOpcodeNot(250);
        {char[] a = {46}; op[250] = getOpcodeTbs(a);}
        {int[] a = {252,253,255}; op[251] = getOpcodeCat(a);}
        {char[] a = {58}; op[252] = getOpcodeTbs(a);}
        op[253] = getOpcodeRep((char)1, (char)4, 254);
        op[254] = getOpcodeRnm(80, 457); // HEXDIG
        op[255] = getOpcodeNot(256);
        {char[] a = {46}; op[256] = getOpcodeTbs(a);}
        {int[] a = {258,259,260,261,262,263,264}; op[257] = getOpcodeCat(a);}
        op[258] = getOpcodeRnm(40, 265); // dec-octet
        {char[] a = {46}; op[259] = getOpcodeTls(a);}
        op[260] = getOpcodeRnm(40, 265); // dec-octet
        {char[] a = {46}; op[261] = getOpcodeTls(a);}
        op[262] = getOpcodeRnm(40, 265); // dec-octet
        {char[] a = {46}; op[263] = getOpcodeTls(a);}
        op[264] = getOpcodeRnm(40, 265); // dec-octet
        op[265] = getOpcodeRep((char)1, (char)3, 266);
        op[266] = getOpcodeRnm(41, 267); // dec-digit
        op[267] = getOpcodeTrg((char)48, (char)57);
        op[268] = getOpcodeRep((char)0, Character.MAX_VALUE, 269);
        op[269] = getOpcodeRnm(43, 270); // reg-name-char
        {int[] a = {271,272,273,274,275,276,277,278,279,280,281}; op[270] = getOpcodeAlt(a);}
        op[271] = getOpcodeTrg((char)97, (char)122);
        op[272] = getOpcodeTrg((char)65, (char)90);
        op[273] = getOpcodeTrg((char)48, (char)57);
        op[274] = getOpcodeRnm(63, 401); // pct-encoded
        {char[] a = {33}; op[275] = getOpcodeTbs(a);}
        {char[] a = {36}; op[276] = getOpcodeTbs(a);}
        op[277] = getOpcodeTrg((char)38, (char)46);
        {char[] a = {59}; op[278] = getOpcodeTbs(a);}
        {char[] a = {61}; op[279] = getOpcodeTbs(a);}
        {char[] a = {95}; op[280] = getOpcodeTbs(a);}
        {char[] a = {126}; op[281] = getOpcodeTbs(a);}
        op[282] = getOpcodeRep((char)0, Character.MAX_VALUE, 283);
        op[283] = getOpcodeRnm(79, 456); // DIGIT
        op[284] = getOpcodeRep((char)0, Character.MAX_VALUE, 285);
        {int[] a = {286,287,288}; op[285] = getOpcodeAlt(a);}
        op[286] = getOpcodeRnm(62, 388); // pchar
        {char[] a = {47}; op[287] = getOpcodeTbs(a);}
        {char[] a = {63}; op[288] = getOpcodeTbs(a);}
        op[289] = getOpcodeRep((char)0, Character.MAX_VALUE, 290);
        {int[] a = {291,292,293}; op[290] = getOpcodeAlt(a);}
        op[291] = getOpcodeRnm(62, 388); // pchar
        {char[] a = {47}; op[292] = getOpcodeTbs(a);}
        {char[] a = {63}; op[293] = getOpcodeTbs(a);}
        {int[] a = {295,296,297,298,302}; op[294] = getOpcodeCat(a);}
        op[295] = getOpcodeRnm(49, 314); // scheme-r
        {char[] a = {58}; op[296] = getOpcodeTls(a);}
        op[297] = getOpcodeRnm(48, 306); // hier-part-r
        op[298] = getOpcodeRep((char)0, (char)1, 299);
        {int[] a = {300,301}; op[299] = getOpcodeCat(a);}
        {char[] a = {63}; op[300] = getOpcodeTls(a);}
        op[301] = getOpcodeRnm(50, 322); // query-r
        op[302] = getOpcodeRep((char)0, (char)1, 303);
        {int[] a = {304,305}; op[303] = getOpcodeCat(a);}
        {char[] a = {35}; op[304] = getOpcodeTls(a);}
        op[305] = getOpcodeRnm(51, 327); // fragment-r
        {int[] a = {307,311,312,313}; op[306] = getOpcodeAlt(a);}
        {int[] a = {308,309,310}; op[307] = getOpcodeCat(a);}
        {char[] a = {47,47}; op[308] = getOpcodeTls(a);}
        op[309] = getOpcodeRnm(52, 332); // authority-d
        op[310] = getOpcodeRnm(56, 364); // path-abempty-r
        op[311] = getOpcodeRnm(57, 368); // path-absolute-r
        op[312] = getOpcodeRnm(58, 377); // path-rootless-r
        op[313] = getOpcodeRnm(59, 383); // path-empty-r
        {int[] a = {315,316}; op[314] = getOpcodeCat(a);}
        op[315] = getOpcodeRnm(77, 452); // ALPHA
        op[316] = getOpcodeRep((char)0, Character.MAX_VALUE, 317);
        {int[] a = {318,319,320,321}; op[317] = getOpcodeAlt(a);}
        op[318] = getOpcodeRnm(77, 452); // ALPHA
        op[319] = getOpcodeRnm(79, 456); // DIGIT
        {char[] a = {43}; op[320] = getOpcodeTbs(a);}
        op[321] = getOpcodeTrg((char)45, (char)46);
        op[322] = getOpcodeRep((char)0, Character.MAX_VALUE, 323);
        {int[] a = {324,325,326}; op[323] = getOpcodeAlt(a);}
        op[324] = getOpcodeRnm(62, 388); // pchar
        {char[] a = {47}; op[325] = getOpcodeTbs(a);}
        {char[] a = {63}; op[326] = getOpcodeTbs(a);}
        op[327] = getOpcodeRep((char)0, Character.MAX_VALUE, 328);
        {int[] a = {329,330,331}; op[328] = getOpcodeAlt(a);}
        op[329] = getOpcodeRnm(62, 388); // pchar
        {char[] a = {47}; op[330] = getOpcodeTbs(a);}
        {char[] a = {63}; op[331] = getOpcodeTbs(a);}
        {int[] a = {333,337,338}; op[332] = getOpcodeCat(a);}
        op[333] = getOpcodeRep((char)0, (char)1, 334);
        {int[] a = {335,336}; op[334] = getOpcodeCat(a);}
        op[335] = getOpcodeRnm(53, 342); // userinfo-d
        {char[] a = {64}; op[336] = getOpcodeTbs(a);}
        op[337] = getOpcodeRnm(54, 355); // host-d
        op[338] = getOpcodeRep((char)0, (char)1, 339);
        {int[] a = {340,341}; op[339] = getOpcodeCat(a);}
        {char[] a = {58}; op[340] = getOpcodeTls(a);}
        op[341] = getOpcodeRnm(55, 362); // port-d
        op[342] = getOpcodeRep((char)0, Character.MAX_VALUE, 343);
        {int[] a = {344,345,346,347,348,349,350,351,352,353,354}; op[343] = getOpcodeAlt(a);}
        op[344] = getOpcodeTrg((char)97, (char)122);
        op[345] = getOpcodeTrg((char)65, (char)90);
        op[346] = getOpcodeTrg((char)48, (char)57);
        op[347] = getOpcodeRnm(63, 401); // pct-encoded
        {char[] a = {33}; op[348] = getOpcodeTbs(a);}
        {char[] a = {36}; op[349] = getOpcodeTbs(a);}
        op[350] = getOpcodeTrg((char)38, (char)46);
        op[351] = getOpcodeTrg((char)58, (char)59);
        {char[] a = {61}; op[352] = getOpcodeTbs(a);}
        {char[] a = {95}; op[353] = getOpcodeTbs(a);}
        {char[] a = {126}; op[354] = getOpcodeTbs(a);}
        {int[] a = {356,357,361}; op[355] = getOpcodeAlt(a);}
        op[356] = getOpcodeRnm(30, 186); // IP-literal
        {int[] a = {358,359}; op[357] = getOpcodeCat(a);}
        op[358] = getOpcodeRnm(39, 257); // IPv4address
        op[359] = getOpcodeNot(360);
        op[360] = getOpcodeRnm(43, 270); // reg-name-char
        op[361] = getOpcodeRnm(42, 268); // reg-name
        op[362] = getOpcodeRep((char)0, Character.MAX_VALUE, 363);
        op[363] = getOpcodeRnm(79, 456); // DIGIT
        op[364] = getOpcodeRep((char)0, Character.MAX_VALUE, 365);
        {int[] a = {366,367}; op[365] = getOpcodeCat(a);}
        {char[] a = {47}; op[366] = getOpcodeTls(a);}
        op[367] = getOpcodeRnm(60, 384); // segment
        {int[] a = {369,370}; op[368] = getOpcodeCat(a);}
        {char[] a = {47}; op[369] = getOpcodeTls(a);}
        op[370] = getOpcodeRep((char)0, (char)1, 371);
        {int[] a = {372,373}; op[371] = getOpcodeCat(a);}
        op[372] = getOpcodeRnm(61, 386); // segment-nz
        op[373] = getOpcodeRep((char)0, Character.MAX_VALUE, 374);
        {int[] a = {375,376}; op[374] = getOpcodeCat(a);}
        {char[] a = {47}; op[375] = getOpcodeTls(a);}
        op[376] = getOpcodeRnm(60, 384); // segment
        {int[] a = {378,379}; op[377] = getOpcodeCat(a);}
        op[378] = getOpcodeRnm(61, 386); // segment-nz
        op[379] = getOpcodeRep((char)0, Character.MAX_VALUE, 380);
        {int[] a = {381,382}; op[380] = getOpcodeCat(a);}
        {char[] a = {47}; op[381] = getOpcodeTls(a);}
        op[382] = getOpcodeRnm(60, 384); // segment
        {char[] a = {}; op[383] = getOpcodeTls(a);}
        op[384] = getOpcodeRep((char)0, Character.MAX_VALUE, 385);
        op[385] = getOpcodeRnm(62, 388); // pchar
        op[386] = getOpcodeRep((char)1, Character.MAX_VALUE, 387);
        op[387] = getOpcodeRnm(62, 388); // pchar
        {int[] a = {389,390,391,392,393,394,395,396,397,398,399,400}; op[388] = getOpcodeAlt(a);}
        op[389] = getOpcodeTrg((char)97, (char)122);
        op[390] = getOpcodeTrg((char)65, (char)90);
        op[391] = getOpcodeTrg((char)48, (char)57);
        op[392] = getOpcodeRnm(63, 401); // pct-encoded
        {char[] a = {33}; op[393] = getOpcodeTbs(a);}
        {char[] a = {36}; op[394] = getOpcodeTbs(a);}
        op[395] = getOpcodeTrg((char)38, (char)46);
        op[396] = getOpcodeTrg((char)58, (char)59);
        {char[] a = {61}; op[397] = getOpcodeTbs(a);}
        {char[] a = {64}; op[398] = getOpcodeTbs(a);}
        {char[] a = {95}; op[399] = getOpcodeTbs(a);}
        {char[] a = {126}; op[400] = getOpcodeTbs(a);}
        {int[] a = {402,403,404}; op[401] = getOpcodeCat(a);}
        {char[] a = {37}; op[402] = getOpcodeTbs(a);}
        op[403] = getOpcodeRnm(80, 457); // HEXDIG
        op[404] = getOpcodeRnm(80, 457); // HEXDIG
        op[405] = getOpcodeRep((char)4, (char)4, 406);
        op[406] = getOpcodeRnm(79, 456); // DIGIT
        op[407] = getOpcodeRep((char)2, (char)2, 408);
        op[408] = getOpcodeRnm(79, 456); // DIGIT
        op[409] = getOpcodeRep((char)2, (char)2, 410);
        op[410] = getOpcodeRnm(79, 456); // DIGIT
        op[411] = getOpcodeRep((char)2, (char)2, 412);
        op[412] = getOpcodeRnm(79, 456); // DIGIT
        op[413] = getOpcodeRep((char)2, (char)2, 414);
        op[414] = getOpcodeRnm(79, 456); // DIGIT
        op[415] = getOpcodeRep((char)2, (char)2, 416);
        op[416] = getOpcodeRnm(79, 456); // DIGIT
        {int[] a = {418,419}; op[417] = getOpcodeCat(a);}
        {char[] a = {46}; op[418] = getOpcodeTls(a);}
        op[419] = getOpcodeRep((char)1, Character.MAX_VALUE, 420);
        op[420] = getOpcodeRnm(79, 456); // DIGIT
        {int[] a = {422,425,426,427}; op[421] = getOpcodeCat(a);}
        {int[] a = {423,424}; op[422] = getOpcodeAlt(a);}
        {char[] a = {43}; op[423] = getOpcodeTls(a);}
        {char[] a = {45}; op[424] = getOpcodeTls(a);}
        op[425] = getOpcodeRnm(67, 411); // time-hour
        {char[] a = {58}; op[426] = getOpcodeTls(a);}
        op[427] = getOpcodeRnm(68, 413); // time-minute
        {int[] a = {429,430}; op[428] = getOpcodeAlt(a);}
        {char[] a = {90}; op[429] = getOpcodeTls(a);}
        op[430] = getOpcodeRnm(71, 421); // time-numoffset
        {int[] a = {432,433,434,435,436,437}; op[431] = getOpcodeCat(a);}
        op[432] = getOpcodeRnm(67, 411); // time-hour
        {char[] a = {58}; op[433] = getOpcodeTls(a);}
        op[434] = getOpcodeRnm(68, 413); // time-minute
        {char[] a = {58}; op[435] = getOpcodeTls(a);}
        op[436] = getOpcodeRnm(69, 415); // time-second
        op[437] = getOpcodeRep((char)0, (char)1, 438);
        op[438] = getOpcodeRnm(70, 417); // time-secfrac
        {int[] a = {440,441,442,443,444}; op[439] = getOpcodeCat(a);}
        op[440] = getOpcodeRnm(64, 405); // date-fullyear
        {char[] a = {45}; op[441] = getOpcodeTls(a);}
        op[442] = getOpcodeRnm(65, 407); // date-month
        {char[] a = {45}; op[443] = getOpcodeTls(a);}
        op[444] = getOpcodeRnm(66, 409); // date-mday
        {int[] a = {446,447}; op[445] = getOpcodeCat(a);}
        op[446] = getOpcodeRnm(73, 431); // partial-time
        op[447] = getOpcodeRnm(72, 428); // time-offset
        {int[] a = {449,450,451}; op[448] = getOpcodeCat(a);}
        op[449] = getOpcodeRnm(74, 439); // full-date
        {char[] a = {84}; op[450] = getOpcodeTls(a);}
        op[451] = getOpcodeRnm(75, 445); // full-time
        {int[] a = {453,454}; op[452] = getOpcodeAlt(a);}
        op[453] = getOpcodeTrg((char)65, (char)90);
        op[454] = getOpcodeTrg((char)97, (char)122);
        {char[] a = {10}; op[455] = getOpcodeTbs(a);}
        op[456] = getOpcodeTrg((char)48, (char)57);
        {int[] a = {458,459,460}; op[457] = getOpcodeAlt(a);}
        op[458] = getOpcodeTrg((char)48, (char)57);
        op[459] = getOpcodeTrg((char)65, (char)70);
        op[460] = getOpcodeTrg((char)97, (char)102);
    }

    public static void display(PrintStream out){
        out.println(";");
        out.println("; com.moonstoneid.siwe.grammar.SiweGrammar");
        out.println(";");
        out.println("; LDT 05/06/2024 ");
        out.println("; modified in several significant ways");
        out.println("; 1) Literal strings are replaced with numbers and ranges (%d32 & %d32-126, etc.) when possible.");
        out.println(";    TRB and especially TRG operators are much more efficient than TLS operators.");
        out.println("; 2) Two rules, authority and URI, are used multiple times in different contexts. These rules will be reproduced and renamed");
        out.println(";    in order to a) recognize the context and b) remove unneccary callback functions for certain contexts.");
        out.println(";    This will simiplify recognizing contexts AND remove unneccesary callbacks");
        out.println("; 2.a) domain is defined as authority-d which is identical to authority except that there will be no");
        out.println(";      callback functions defined on authority-d or any of its *-d components.");
        out.println("; 2.b) The resource URI is defined as URI-r and its components defined as *-r.");
        out.println(";      In this way, callback functions can be defined on URI and is components while");
        out.println(";      leaving URI-r to be parsed identically with no unnecessary callback functions to slow it down.");
        out.println("; 3) IPv6address does not work because of APG's \"first-success disambiguation\" and \"greedy\" repetitions.");
        out.println(";    IPv6address redefined and validations moved to callback functions (semantic vs syntactic validation)");
        out.println(";    Redefinition requires negative look-ahead operators, https://en.wikipedia.org/wiki/Syntactic_predicate");
        out.println(";    That is SABNF instead of simple ABNF.");
        out.println("; 4) IPv4address fails because of \"first-success disambiguation\".");
        out.println(";    This could be fixed with rearrangement of the alternative terms. However, it would still not");
        out.println(";    accept zero-padded (leading zeros) decimal octets.");
        out.println(";    Therefore, IPv4address is also done with callback functions and semantic validation.");
        out.println("; 5) The negative look-ahead operator is also needed in the definition of host to");
        out.println(";    prevent failure with a reg-name that begins with an IPv4 address.");
        out.println("; 6) NOTE: host = 1.1.1.256 is a valid host name even though it is an invalid IPv4address.");
        out.println(";          The IPv4address alternative fails but the reg-name alternative succeeds.");
        out.println("; 7) The Ethereum spec (https://eips.ethereum.org/EIPS/eip-4361) message format ABNF");
        out.println(";    allows for empty statements. Because of the \"first success disambiguation\" of APG");
        out.println(";    the an explicit \"empty-statement\" rule is required to match the spec's intent.");
        out.println("");
        out.println("");
        out.println("sign-in-with-ethereum =");
        out.println("    oscheme domain %s\" wants you to sign in with your Ethereum account:\" LF");
        out.println("    address LF");
        out.println("    ((LF statement LF LF) / empty-statement / (LF LF))");
        out.println("    %s\"URI: \" URI LF");
        out.println("    %s\"Version: \" version LF");
        out.println("    %s\"Chain ID: \" chain-id LF");
        out.println("    %s\"Nonce: \" nonce LF");
        out.println("    %s\"Issued At: \" issued-at");
        out.println("    [ LF ex-title expiration-time ]");
        out.println("    [ LF nb-title not-before ]");
        out.println("    [ LF ri-title request-id ]");
        out.println("    [ LF re-title resources ]");
        out.println("ex-title        = %s\"Expiration Time: \"");
        out.println("nb-title        = %s\"Not Before: \"");
        out.println("ri-title        = %s\"Request ID: \"");
        out.println("re-title        = %s\"Resources:\"");
        out.println("oscheme         = [ ALPHA *( ALPHA / DIGIT / %d43 / %d45-46 ) \"://\" ]");
        out.println("domain          = authority-d");
        out.println("address         = \"0x\" 40*40HEXDIG");
        out.println("    ; Must also conform to captilization");
        out.println("    ; checksum encoding specified in EIP-55");
        out.println("    ; where applicable (EOAs).");
        out.println("");
        out.println("statement       = 1*( %d97-122 / %d65-90 / %d48-57 / %d32-33 / %d35-36 / %d38-59 / %d61 / %d63-64 / %d91 / %d93 / %d95 / %d126)");
        out.println("    ; The purpose is to exclude LF (line breaks).");
        out.println("    ; LDT 10/04/2023: Do you mean %d32-126? All printing characters");
        out.println("empty-statement = LF LF LF");
        out.println("version         = \"1\"");
        out.println("nonce           = 8*( ALPHA / DIGIT )");
        out.println("issued-at       = date-time");
        out.println("expiration-time = date-time");
        out.println("not-before      = date-time");
        out.println("request-id      = *pchar");
        out.println("chain-id        = 1*DIGIT");
        out.println("    ; See EIP-155 for valid CHAIN_IDs.");
        out.println("resources       = *( LF resource )");
        out.println("resource        = \"- \" URI-r");
        out.println("");
        out.println("; ------------------------------------------------------------------------------");
        out.println("; RFC 3986");
        out.println("");
        out.println("URI           = scheme \":\" hier-part [ \"?\" query ] [ \"#\" fragment ]");
        out.println("hier-part     = \"//\" authority path-abempty");
        out.println("              / path-absolute");
        out.println("              / path-rootless");
        out.println("              / path-empty");
        out.println("scheme        = ALPHA *( ALPHA / DIGIT / %d43 / %d45-46 )");
        out.println("authority     = [ userinfo-at ] host [ \":\" port ]");
        out.println("path-abempty  = *( \"/\" segment )");
        out.println("path-absolute = \"/\" [ segment-nz *( \"/\" segment ) ]");
        out.println("path-rootless = segment-nz *( \"/\" segment )");
        out.println("path-empty    = \"\"");
        out.println("userinfo-at   = userinfo %d64");
        out.println("                ; userinfo redefined to include the \"@\" so that it will fail without it");
        out.println("                ; otherwise userinfo can match host and then the parser will backtrack");
        out.println("                ; incorrectly keeping the captured userinfo phrase");
        out.println("userinfo      = *(%d97-122 / %d65-90 / %d48-57 / pct-encoded / %d33 / %d36 / %d38-46 / %d58-59 / %d61 / %d95 / %d126)");
        out.println("host          = IP-literal / (IPv4address !reg-name-char) / reg-name");
        out.println("                ; negative look-ahead required to prevent IPv4address from being recognized as first part of reg-name");
        out.println("                ; same fix as https://github.com/garycourt/uri-js/issues/4");
        out.println("IP-literal    = \"[\" ( IPv6address / IPvFuture  ) \"]\"");
        out.println("IPvFuture     = \"v\" 1*HEXDIG \".\" 1*( %d97-122 / %d65-90 / %d48-57 / %d33 / %d36 /%d38-46 / %d58-59 /%d61 /%d95 / %d126 )");
        out.println("IPv6address   = nodcolon / dcolon");
        out.println("nodcolon      = (h16n *h16cn) [%d58 IPv4address]");
        out.println("dcolon        = [h16 *h16c] %d58.58 (((h16n *h16cn) [%d58 IPv4address]) / [IPv4address])");
        out.println("h16           = 1*4HEXDIG");
        out.println("h16c          = %d58 1*4HEXDIG");
        out.println("h16n          = 1*4HEXDIG !%d46");
        out.println("h16cn         = %d58 1*4HEXDIG !%d46");
        out.println("IPv4address   = dec-octet \".\" dec-octet \".\" dec-octet \".\" dec-octet");
        out.println("; Here we will will use callback functions to evaluate and validate the (possibly zero-padded) dec-octet.");
        out.println("dec-octet     =  1*3dec-digit");
        out.println("dec-digit     = %d48-57");
        out.println("reg-name      = *reg-name-char");
        out.println("reg-name-char = %d97-122 / %d65-90 / %d48-57 / pct-encoded / %d33 / %d36 / %d38-46 / %d59 / %d61 /%d95 / %d126");
        out.println("port          = *DIGIT");
        out.println("query         = *(pchar / %d47 / %d63)");
        out.println("fragment      = *(pchar / %d47 / %d63)");
        out.println("");
        out.println("; URI-r is a redefiniton of URI but without the callback functions attached to it");
        out.println("; it reuses athority-d from domain ");
        out.println("URI-r         = scheme-r \":\" hier-part-r [ \"?\" query-r ] [ \"#\" fragment-r ]");
        out.println("hier-part-r   = \"//\" authority-d path-abempty-r");
        out.println("              / path-absolute-r");
        out.println("              / path-rootless-r");
        out.println("              / path-empty-r");
        out.println("scheme-r      = ALPHA *( ALPHA / DIGIT / %d43 / %d45-46 )");
        out.println("query-r       = *(pchar / %d47 / %d63)");
        out.println("fragment-r    = *(pchar / %d47 / %d63)");
        out.println("");
        out.println("; authority-d is a redefinition of authority for capturing the domian phrase");
        out.println("; but without callback functions ");
        out.println("; it is reused for URI- for the same reason               ");
        out.println("authority-d   = [ userinfo-d %d64 ] host-d [ \":\" port-d ]");
        out.println("userinfo-d    = *(%d97-122 / %d65-90 / %d48-57 / pct-encoded / %d33 / %d36 / %d38-46 / %d58-59 / %d61 / %d95 / %d126)");
        out.println("host-d        = IP-literal / (IPv4address !reg-name-char) / reg-name");
        out.println("port-d        = *DIGIT");
        out.println("");
        out.println("; for use with URI-r");
        out.println("path-abempty-r  = *( \"/\" segment )");
        out.println("path-absolute-r = \"/\" [ segment-nz *( \"/\" segment ) ]");
        out.println("path-rootless-r = segment-nz *( \"/\" segment )");
        out.println("path-empty-r    = \"\"");
        out.println("segment       = *pchar");
        out.println("segment-nz    = 1*pchar");
        out.println("pchar         = (%d97-122 / %d65-90 / %d48-57 / pct-encoded / %d33 / %d36 / %d38-46 /%d58-59 / %d61 / %d64 / %d95 / %d126)");
        out.println("pct-encoded   = %d37 HEXDIG HEXDIG");
        out.println("");
        out.println("; no longer needed - expanded for all usage for fewer branches in the parse there");
        out.println("; and more efficient use of the TBS & TRG operators in place of TLS and rule names");
        out.println("; does not work with APG probably because of \"first-success disambiguation\" and greedy repetitions.");
        out.println("; will replace with semantic checking of valid number of h16s");
        out.println(";IPv6address   =                            6( h16 \":\" ) ls32");
        out.println(";              /                       \"::\" 5( h16 \":\" ) ls32");
        out.println(";              / [               h16 ] \"::\" 4( h16 \":\" ) ls32");
        out.println(";              / [ *1( h16 \":\" ) h16 ] \"::\" 3( h16 \":\" ) ls32");
        out.println(";              / [ *2( h16 \":\" ) h16 ] \"::\" 2( h16 \":\" ) ls32");
        out.println(";              / [ *3( h16 \":\" ) h16 ] \"::\"    h16 \":\"   ls32");
        out.println(";              / [ *4( h16 \":\" ) h16 ] \"::\"              ls32");
        out.println(";              / [ *5( h16 \":\" ) h16 ] \"::\"              h16");
        out.println(";              / [ *6( h16 \":\" ) h16 ] \"::\"");
        out.println(";ls32          = ( h16 \":\" h16 ) / IPv4address");
        out.println("; dec-octet does not work because of \"first-success disambiguation\".");
        out.println("; Must have the longest (3-digit) numbers first.");
        out.println("; Even so, this form does not accept leading zeros.");
        out.println("; There does not seem to be a clear standard for this (https://en.wikipedia.org/wiki/Dot-decimal_notation)");
        out.println("; however and early RFC 790 did show leading-zero padding of the three digits.");
        out.println(";dec-octet     = DIGIT                 ; 0-9");
        out.println(";                 / %x31-39 DIGIT         ; 10-99");
        out.println(";                 / \"1\" 2DIGIT            ; 100-199");
        out.println(";                 / \"2\" %x30-34 DIGIT     ; 200-249");
        out.println(";                 / \"25\" %x30-35          ; 250-255");
        out.println(";statement = 1*( reserved / unreserved / \" \" )");
        out.println(";scheme        = ALPHA *( ALPHA / DIGIT / \"+\" / \"-\" / \".\" )");
        out.println(";authority     = [ userinfo \"@\" ] host [ \":\" port ]");
        out.println(";userinfo      = *( unreserved / pct-encoded / sub-delims / \":\" )");
        out.println(";query         = *( pchar / \"/\" / \"?\" )");
        out.println(";fragment      = *( pchar / \"/\" / \"?\" )");
        out.println(";IPvFuture     = \"v\" 1*HEXDIG \".\" 1*( unreserved / sub-delims / \":\" )");
        out.println(";reg-name      = *( unreserved / pct-encoded / sub-delims )");
        out.println(";pct-encoded   = \"%\" HEXDIG HEXDIG");
        out.println(";pchar         = unreserved / pct-encoded / sub-delims / \":\" / \"@\"");
        out.println(";path-empty    = 0pchar; deprecated - empty literal string, \"\", is more efficient ");
        out.println(";unreserved    = ALPHA / DIGIT / \"-\" / \".\" / \"_\" / \"~\"");
        out.println(";reserved      = gen-delims / sub-delims");
        out.println(";gen-delims    = \":\" / \"/\" / \"?\" / \"#\" / \"[\" / \"]\" / \"@\"");
        out.println(";sub-delims    = \"!\" / \"$\" / \"&\" / \"'\" / \"(\" / \")\"");
        out.println(";              / \"*\" / \"+\" / \",\" / \";\" / \"=\"");
        out.println(";HEXDIG         =  DIGIT / \"A\" / \"B\" / \"C\" / \"D\" / \"E\" / \"F\"");
        out.println("");
        out.println("; ------------------------------------------------------------------------------");
        out.println("; RFC 3339");
        out.println("");
        out.println("date-fullyear   = 4DIGIT");
        out.println("date-month      = 2DIGIT  ; 01-12");
        out.println("date-mday       = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on");
        out.println("                          ; month/year");
        out.println("time-hour       = 2DIGIT  ; 00-23");
        out.println("time-minute     = 2DIGIT  ; 00-59");
        out.println("time-second     = 2DIGIT  ; 00-58, 00-59, 00-60 based on leap second");
        out.println("                          ; rules");
        out.println("time-secfrac    = \".\" 1*DIGIT");
        out.println("time-numoffset  = (\"+\" / \"-\") time-hour \":\" time-minute");
        out.println("time-offset     = \"Z\" / time-numoffset");
        out.println("");
        out.println("partial-time    = time-hour \":\" time-minute \":\" time-second");
        out.println("                  [time-secfrac]");
        out.println("full-date       = date-fullyear \"-\" date-month \"-\" date-mday");
        out.println("full-time       = partial-time time-offset");
        out.println("");
        out.println("date-time       = full-date \"T\" full-time");
        out.println("");
        out.println("; ------------------------------------------------------------------------------");
        out.println("; RFC 5234");
        out.println("");
        out.println("ALPHA          =  %x41-5A / %x61-7A   ; A-Z / a-z");
        out.println("LF             =  %x0A");
        out.println("                  ; linefeed");
        out.println("DIGIT          =  %x30-39");
        out.println("                  ; 0-9");
        out.println("HEXDIG         = %d48-57 / %d65-70 / %d97-102");
    }
}
