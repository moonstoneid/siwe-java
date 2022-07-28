// This class has been generated automatically
// from an SABNF grammar by Java APG, Verision 1.1.0.
// Copyright (c) 2021 Lowell D. Thomas, all rights reserved.
// Licensed under the 2-Clause BSD License.
package com.moonstoneid.siwe.grammar;

import java.io.PrintStream;

import apg.Grammar;

public class SiweGrammar extends Grammar {

    private static SiweGrammar factoryInstance = null;

    public static Grammar getInstance() {
        if (factoryInstance == null) {
            factoryInstance = new SiweGrammar(getRules(), getUdts(), getOpcodes());
        }
        return factoryInstance;
    }

    public enum RuleNames {
        ADDRESS("address", 2, 47, 4),
        ALPHA("ALPHA", 55, 393, 3),
        AUTHORITY("authority", 16, 104, 10),
        CHAIN_ID("chain-id", 10, 66, 2),
        DATE_FULLYEAR("date-fullyear", 42, 346, 2),
        DATE_MDAY("date-mday", 44, 350, 2),
        DATE_MONTH("date-month", 43, 348, 2),
        DATE_TIME("date-time", 54, 389, 4),
        DEC_OCTET("dec-octet", 26, 250, 16),
        DIGIT("DIGIT", 57, 397, 1),
        DOMAIN("domain", 1, 46, 1),
        EXPIRATION_TIME("expiration-time", 7, 62, 1),
        FRAGMENT("fragment", 36, 307, 5),
        FULL_DATE("full-date", 52, 380, 6),
        FULL_TIME("full-time", 53, 386, 3),
        GEN_DELIMS("gen-delims", 40, 326, 8),
        H16("h16", 23, 234, 2),
        HEXDIG("HEXDIG", 58, 398, 8),
        HIER_PART("hier-part", 14, 87, 8),
        HOST("host", 18, 120, 4),
        IP_LITERAL("IP-literal", 20, 126, 6),
        IPV4ADDRESS("IPv4address", 25, 242, 8),
        IPV6ADDRESS("IPv6address", 22, 142, 92),
        IPVFUTURE("IPvFuture", 21, 132, 10),
        ISSUED_AT("issued-at", 6, 61, 1),
        LF("LF", 56, 396, 1),
        LS32("ls32", 24, 236, 6),
        NONCE("nonce", 5, 57, 4),
        NOT_BEFORE("not-before", 8, 63, 1),
        PARTIAL_TIME("partial-time", 51, 372, 8),
        PATH_ABEMPTY("path-abempty", 28, 271, 4),
        PATH_ABSOLUTE("path-absolute", 29, 275, 9),
        PATH_EMPTY("path-empty", 31, 290, 2),
        PATH_ROOTLESS("path-rootless", 30, 284, 6),
        PCHAR("pchar", 34, 296, 6),
        PCT_ENCODED("pct-encoded", 37, 312, 4),
        PORT("port", 19, 124, 2),
        QUERY("query", 35, 302, 5),
        REG_NAME("reg-name", 27, 266, 5),
        REQUEST_ID("request-id", 9, 64, 2),
        RESERVED("reserved", 39, 323, 3),
        RESOURCE("resource", 12, 72, 3),
        RESOURCES("resources", 11, 68, 4),
        SCHEME("scheme", 15, 95, 9),
        SEGMENT("segment", 32, 292, 2),
        SEGMENT_NZ("segment-nz", 33, 294, 2),
        SIGN_IN_WITH_ETHEREUM("sign-in-with-ethereum", 0, 0, 46),
        STATEMENT("statement", 3, 51, 5),
        SUB_DELIMS("sub-delims", 41, 334, 12),
        TIME_HOUR("time-hour", 45, 352, 2),
        TIME_MINUTE("time-minute", 46, 354, 2),
        TIME_NUMOFFSET("time-numoffset", 49, 362, 7),
        TIME_OFFSET("time-offset", 50, 369, 3),
        TIME_SECFRAC("time-secfrac", 48, 358, 4),
        TIME_SECOND("time-second", 47, 356, 2),
        UNRESERVED("unreserved", 38, 316, 7),
        URI("URI", 13, 75, 12),
        USERINFO("userinfo", 17, 114, 6),
        VERSION("version", 4, 56, 1);

        private final String name;
        private final int id;
        private final int offset;
        private final int count;

        RuleNames(String string, int id, int offset, int count){
            this.name = string;
            this.id = id;
            this.offset = offset;
            this.count = count;
        }

        public String ruleName() {
            return name;
        }

        public String ruleEnumName() {
            return name();
        }

        public int ruleID() {
            return id;
        }

        private int opcodeOffset() {
            return offset;
        }

        private int opcodeCount() {
            return count;
        }

    }

    private SiweGrammar(Rule[] rules, Udt[] udts, Opcode[] opcodes) {
        super(rules, udts, opcodes);
    }

    private static Rule[] getRules() {
    	Rule[] rules = new Rule[59];
        for (RuleNames r : RuleNames.values()) {
            rules[r.ruleID()] = getRule(r.ruleID(), r.ruleName(), r.opcodeOffset(), r.opcodeCount());
        }
        return rules;
    }

    private static Udt[] getUdts() {
    	return new Udt[0];
    }

    private static Opcode[] getOpcodes() {
    	Opcode[] op = new Opcode[406];
    	addOpcodes00(op);
        return op;
    }

    private static void addOpcodes00(Opcode[] op) {
        {int[] a = {1,2,3,4,5,6,7,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,31,36,41}; op[0] = getOpcodeCat(a);}
        op[1] = getOpcodeRnm(1, 46); // domain
        {char[] a = {32,119,97,110,116,115,32,121,111,117,32,116,111,32,115,105,103,110,32,105,110,32,119,105,116,104,32,121,111,117,114,32,69,116,104,101,114,101,117,109,32,97,99,99,111,117,110,116,58}; op[2] = getOpcodeTbs(a);}
        op[3] = getOpcodeRnm(56, 396); // LF
        op[4] = getOpcodeRnm(2, 47); // address
        op[5] = getOpcodeRnm(56, 396); // LF
        op[6] = getOpcodeRnm(56, 396); // LF
        op[7] = getOpcodeRep((char)0, (char)1, 8);
        {int[] a = {9,10}; op[8] = getOpcodeCat(a);}
        op[9] = getOpcodeRnm(3, 51); // statement
        op[10] = getOpcodeRnm(56, 396); // LF
        op[11] = getOpcodeRnm(56, 396); // LF
        {char[] a = {85,82,73,58,32}; op[12] = getOpcodeTbs(a);}
        op[13] = getOpcodeRnm(13, 75); // URI
        op[14] = getOpcodeRnm(56, 396); // LF
        {char[] a = {86,101,114,115,105,111,110,58,32}; op[15] = getOpcodeTbs(a);}
        op[16] = getOpcodeRnm(4, 56); // version
        op[17] = getOpcodeRnm(56, 396); // LF
        {char[] a = {67,104,97,105,110,32,73,68,58,32}; op[18] = getOpcodeTbs(a);}
        op[19] = getOpcodeRnm(10, 66); // chain-id
        op[20] = getOpcodeRnm(56, 396); // LF
        {char[] a = {78,111,110,99,101,58,32}; op[21] = getOpcodeTbs(a);}
        op[22] = getOpcodeRnm(5, 57); // nonce
        op[23] = getOpcodeRnm(56, 396); // LF
        {char[] a = {73,115,115,117,101,100,32,65,116,58,32}; op[24] = getOpcodeTbs(a);}
        op[25] = getOpcodeRnm(6, 61); // issued-at
        op[26] = getOpcodeRep((char)0, (char)1, 27);
        {int[] a = {28,29,30}; op[27] = getOpcodeCat(a);}
        op[28] = getOpcodeRnm(56, 396); // LF
        {char[] a = {69,120,112,105,114,97,116,105,111,110,32,84,105,109,101,58,32}; op[29] = getOpcodeTbs(a);}
        op[30] = getOpcodeRnm(7, 62); // expiration-time
        op[31] = getOpcodeRep((char)0, (char)1, 32);
        {int[] a = {33,34,35}; op[32] = getOpcodeCat(a);}
        op[33] = getOpcodeRnm(56, 396); // LF
        {char[] a = {78,111,116,32,66,101,102,111,114,101,58,32}; op[34] = getOpcodeTbs(a);}
        op[35] = getOpcodeRnm(8, 63); // not-before
        op[36] = getOpcodeRep((char)0, (char)1, 37);
        {int[] a = {38,39,40}; op[37] = getOpcodeCat(a);}
        op[38] = getOpcodeRnm(56, 396); // LF
        {char[] a = {82,101,113,117,101,115,116,32,73,68,58,32}; op[39] = getOpcodeTbs(a);}
        op[40] = getOpcodeRnm(9, 64); // request-id
        op[41] = getOpcodeRep((char)0, (char)1, 42);
        {int[] a = {43,44,45}; op[42] = getOpcodeCat(a);}
        op[43] = getOpcodeRnm(56, 396); // LF
        {char[] a = {82,101,115,111,117,114,99,101,115,58}; op[44] = getOpcodeTbs(a);}
        op[45] = getOpcodeRnm(11, 68); // resources
        op[46] = getOpcodeRnm(16, 104); // authority
        {int[] a = {48,49}; op[47] = getOpcodeCat(a);}
        {char[] a = {48,120}; op[48] = getOpcodeTls(a);}
        op[49] = getOpcodeRep((char)40, (char)40, 50);
        op[50] = getOpcodeRnm(58, 398); // HEXDIG
        op[51] = getOpcodeRep((char)1, Character.MAX_VALUE, 52);
        {int[] a = {53,54,55}; op[52] = getOpcodeAlt(a);}
        op[53] = getOpcodeRnm(39, 323); // reserved
        op[54] = getOpcodeRnm(38, 316); // unreserved
        {char[] a = {32}; op[55] = getOpcodeTls(a);}
        {char[] a = {49}; op[56] = getOpcodeTls(a);}
        op[57] = getOpcodeRep((char)8, Character.MAX_VALUE, 58);
        {int[] a = {59,60}; op[58] = getOpcodeAlt(a);}
        op[59] = getOpcodeRnm(55, 393); // ALPHA
        op[60] = getOpcodeRnm(57, 397); // DIGIT
        op[61] = getOpcodeRnm(54, 389); // date-time
        op[62] = getOpcodeRnm(54, 389); // date-time
        op[63] = getOpcodeRnm(54, 389); // date-time
        op[64] = getOpcodeRep((char)0, Character.MAX_VALUE, 65);
        op[65] = getOpcodeRnm(34, 296); // pchar
        op[66] = getOpcodeRep((char)1, Character.MAX_VALUE, 67);
        op[67] = getOpcodeRnm(57, 397); // DIGIT
        op[68] = getOpcodeRep((char)0, Character.MAX_VALUE, 69);
        {int[] a = {70,71}; op[69] = getOpcodeCat(a);}
        op[70] = getOpcodeRnm(56, 396); // LF
        op[71] = getOpcodeRnm(12, 72); // resource
        {int[] a = {73,74}; op[72] = getOpcodeCat(a);}
        {char[] a = {45,32}; op[73] = getOpcodeTls(a);}
        op[74] = getOpcodeRnm(13, 75); // URI
        {int[] a = {76,77,78,79,83}; op[75] = getOpcodeCat(a);}
        op[76] = getOpcodeRnm(15, 95); // scheme
        {char[] a = {58}; op[77] = getOpcodeTls(a);}
        op[78] = getOpcodeRnm(14, 87); // hier-part
        op[79] = getOpcodeRep((char)0, (char)1, 80);
        {int[] a = {81,82}; op[80] = getOpcodeCat(a);}
        {char[] a = {63}; op[81] = getOpcodeTls(a);}
        op[82] = getOpcodeRnm(35, 302); // query
        op[83] = getOpcodeRep((char)0, (char)1, 84);
        {int[] a = {85,86}; op[84] = getOpcodeCat(a);}
        {char[] a = {35}; op[85] = getOpcodeTls(a);}
        op[86] = getOpcodeRnm(36, 307); // fragment
        {int[] a = {88,92,93,94}; op[87] = getOpcodeAlt(a);}
        {int[] a = {89,90,91}; op[88] = getOpcodeCat(a);}
        {char[] a = {47,47}; op[89] = getOpcodeTls(a);}
        op[90] = getOpcodeRnm(16, 104); // authority
        op[91] = getOpcodeRnm(28, 271); // path-abempty
        op[92] = getOpcodeRnm(29, 275); // path-absolute
        op[93] = getOpcodeRnm(30, 284); // path-rootless
        op[94] = getOpcodeRnm(31, 290); // path-empty
        {int[] a = {96,97}; op[95] = getOpcodeCat(a);}
        op[96] = getOpcodeRnm(55, 393); // ALPHA
        op[97] = getOpcodeRep((char)0, Character.MAX_VALUE, 98);
        {int[] a = {99,100,101,102,103}; op[98] = getOpcodeAlt(a);}
        op[99] = getOpcodeRnm(55, 393); // ALPHA
        op[100] = getOpcodeRnm(57, 397); // DIGIT
        {char[] a = {43}; op[101] = getOpcodeTls(a);}
        {char[] a = {45}; op[102] = getOpcodeTls(a);}
        {char[] a = {46}; op[103] = getOpcodeTls(a);}
        {int[] a = {105,109,110}; op[104] = getOpcodeCat(a);}
        op[105] = getOpcodeRep((char)0, (char)1, 106);
        {int[] a = {107,108}; op[106] = getOpcodeCat(a);}
        op[107] = getOpcodeRnm(17, 114); // userinfo
        {char[] a = {64}; op[108] = getOpcodeTls(a);}
        op[109] = getOpcodeRnm(18, 120); // host
        op[110] = getOpcodeRep((char)0, (char)1, 111);
        {int[] a = {112,113}; op[111] = getOpcodeCat(a);}
        {char[] a = {58}; op[112] = getOpcodeTls(a);}
        op[113] = getOpcodeRnm(19, 124); // port
        op[114] = getOpcodeRep((char)0, Character.MAX_VALUE, 115);
        {int[] a = {116,117,118,119}; op[115] = getOpcodeAlt(a);}
        op[116] = getOpcodeRnm(38, 316); // unreserved
        op[117] = getOpcodeRnm(37, 312); // pct-encoded
        op[118] = getOpcodeRnm(41, 334); // sub-delims
        {char[] a = {58}; op[119] = getOpcodeTls(a);}
        {int[] a = {121,122,123}; op[120] = getOpcodeAlt(a);}
        op[121] = getOpcodeRnm(20, 126); // IP-literal
        op[122] = getOpcodeRnm(25, 242); // IPv4address
        op[123] = getOpcodeRnm(27, 266); // reg-name
        op[124] = getOpcodeRep((char)0, Character.MAX_VALUE, 125);
        op[125] = getOpcodeRnm(57, 397); // DIGIT
        {int[] a = {127,128,131}; op[126] = getOpcodeCat(a);}
        {char[] a = {91}; op[127] = getOpcodeTls(a);}
        {int[] a = {129,130}; op[128] = getOpcodeAlt(a);}
        op[129] = getOpcodeRnm(22, 142); // IPv6address
        op[130] = getOpcodeRnm(21, 132); // IPvFuture
        {char[] a = {93}; op[131] = getOpcodeTls(a);}
        {int[] a = {133,134,136,137}; op[132] = getOpcodeCat(a);}
        {char[] a = {118}; op[133] = getOpcodeTls(a);}
        op[134] = getOpcodeRep((char)1, Character.MAX_VALUE, 135);
        op[135] = getOpcodeRnm(58, 398); // HEXDIG
        {char[] a = {46}; op[136] = getOpcodeTls(a);}
        op[137] = getOpcodeRep((char)1, Character.MAX_VALUE, 138);
        {int[] a = {139,140,141}; op[138] = getOpcodeAlt(a);}
        op[139] = getOpcodeRnm(38, 316); // unreserved
        op[140] = getOpcodeRnm(41, 334); // sub-delims
        {char[] a = {58}; op[141] = getOpcodeTls(a);}
        {int[] a = {143,149,156,165,179,193,205,215,225}; op[142] = getOpcodeAlt(a);}
        {int[] a = {144,148}; op[143] = getOpcodeCat(a);}
        op[144] = getOpcodeRep((char)6, (char)6, 145);
        {int[] a = {146,147}; op[145] = getOpcodeCat(a);}
        op[146] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[147] = getOpcodeTls(a);}
        op[148] = getOpcodeRnm(24, 236); // ls32
        {int[] a = {150,151,155}; op[149] = getOpcodeCat(a);}
        {char[] a = {58,58}; op[150] = getOpcodeTls(a);}
        op[151] = getOpcodeRep((char)5, (char)5, 152);
        {int[] a = {153,154}; op[152] = getOpcodeCat(a);}
        op[153] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[154] = getOpcodeTls(a);}
        op[155] = getOpcodeRnm(24, 236); // ls32
        {int[] a = {157,159,160,164}; op[156] = getOpcodeCat(a);}
        op[157] = getOpcodeRep((char)0, (char)1, 158);
        op[158] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58,58}; op[159] = getOpcodeTls(a);}
        op[160] = getOpcodeRep((char)4, (char)4, 161);
        {int[] a = {162,163}; op[161] = getOpcodeCat(a);}
        op[162] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[163] = getOpcodeTls(a);}
        op[164] = getOpcodeRnm(24, 236); // ls32
        {int[] a = {166,173,174,178}; op[165] = getOpcodeCat(a);}
        op[166] = getOpcodeRep((char)0, (char)1, 167);
        {int[] a = {168,172}; op[167] = getOpcodeCat(a);}
        op[168] = getOpcodeRep((char)0, (char)1, 169);
        {int[] a = {170,171}; op[169] = getOpcodeCat(a);}
        op[170] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[171] = getOpcodeTls(a);}
        op[172] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58,58}; op[173] = getOpcodeTls(a);}
        op[174] = getOpcodeRep((char)3, (char)3, 175);
        {int[] a = {176,177}; op[175] = getOpcodeCat(a);}
        op[176] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[177] = getOpcodeTls(a);}
        op[178] = getOpcodeRnm(24, 236); // ls32
        {int[] a = {180,187,188,192}; op[179] = getOpcodeCat(a);}
        op[180] = getOpcodeRep((char)0, (char)1, 181);
        {int[] a = {182,186}; op[181] = getOpcodeCat(a);}
        op[182] = getOpcodeRep((char)0, (char)2, 183);
        {int[] a = {184,185}; op[183] = getOpcodeCat(a);}
        op[184] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[185] = getOpcodeTls(a);}
        op[186] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58,58}; op[187] = getOpcodeTls(a);}
        op[188] = getOpcodeRep((char)2, (char)2, 189);
        {int[] a = {190,191}; op[189] = getOpcodeCat(a);}
        op[190] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[191] = getOpcodeTls(a);}
        op[192] = getOpcodeRnm(24, 236); // ls32
        {int[] a = {194,201,202,203,204}; op[193] = getOpcodeCat(a);}
        op[194] = getOpcodeRep((char)0, (char)1, 195);
        {int[] a = {196,200}; op[195] = getOpcodeCat(a);}
        op[196] = getOpcodeRep((char)0, (char)3, 197);
        {int[] a = {198,199}; op[197] = getOpcodeCat(a);}
        op[198] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[199] = getOpcodeTls(a);}
        op[200] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58,58}; op[201] = getOpcodeTls(a);}
        op[202] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[203] = getOpcodeTls(a);}
        op[204] = getOpcodeRnm(24, 236); // ls32
        {int[] a = {206,213,214}; op[205] = getOpcodeCat(a);}
        op[206] = getOpcodeRep((char)0, (char)1, 207);
        {int[] a = {208,212}; op[207] = getOpcodeCat(a);}
        op[208] = getOpcodeRep((char)0, (char)4, 209);
        {int[] a = {210,211}; op[209] = getOpcodeCat(a);}
        op[210] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[211] = getOpcodeTls(a);}
        op[212] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58,58}; op[213] = getOpcodeTls(a);}
        op[214] = getOpcodeRnm(24, 236); // ls32
        {int[] a = {216,223,224}; op[215] = getOpcodeCat(a);}
        op[216] = getOpcodeRep((char)0, (char)1, 217);
        {int[] a = {218,222}; op[217] = getOpcodeCat(a);}
        op[218] = getOpcodeRep((char)0, (char)5, 219);
        {int[] a = {220,221}; op[219] = getOpcodeCat(a);}
        op[220] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[221] = getOpcodeTls(a);}
        op[222] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58,58}; op[223] = getOpcodeTls(a);}
        op[224] = getOpcodeRnm(23, 234); // h16
        {int[] a = {226,233}; op[225] = getOpcodeCat(a);}
        op[226] = getOpcodeRep((char)0, (char)1, 227);
        {int[] a = {228,232}; op[227] = getOpcodeCat(a);}
        op[228] = getOpcodeRep((char)0, (char)6, 229);
        {int[] a = {230,231}; op[229] = getOpcodeCat(a);}
        op[230] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[231] = getOpcodeTls(a);}
        op[232] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58,58}; op[233] = getOpcodeTls(a);}
        op[234] = getOpcodeRep((char)1, (char)4, 235);
        op[235] = getOpcodeRnm(58, 398); // HEXDIG
        {int[] a = {237,241}; op[236] = getOpcodeAlt(a);}
        {int[] a = {238,239,240}; op[237] = getOpcodeCat(a);}
        op[238] = getOpcodeRnm(23, 234); // h16
        {char[] a = {58}; op[239] = getOpcodeTls(a);}
        op[240] = getOpcodeRnm(23, 234); // h16
        op[241] = getOpcodeRnm(25, 242); // IPv4address
        {int[] a = {243,244,245,246,247,248,249}; op[242] = getOpcodeCat(a);}
        op[243] = getOpcodeRnm(26, 250); // dec-octet
        {char[] a = {46}; op[244] = getOpcodeTls(a);}
        op[245] = getOpcodeRnm(26, 250); // dec-octet
        {char[] a = {46}; op[246] = getOpcodeTls(a);}
        op[247] = getOpcodeRnm(26, 250); // dec-octet
        {char[] a = {46}; op[248] = getOpcodeTls(a);}
        op[249] = getOpcodeRnm(26, 250); // dec-octet
        {int[] a = {251,252,255,259,263}; op[250] = getOpcodeAlt(a);}
        op[251] = getOpcodeRnm(57, 397); // DIGIT
        {int[] a = {253,254}; op[252] = getOpcodeCat(a);}
        op[253] = getOpcodeTrg((char)49, (char)57);
        op[254] = getOpcodeRnm(57, 397); // DIGIT
        {int[] a = {256,257}; op[255] = getOpcodeCat(a);}
        {char[] a = {49}; op[256] = getOpcodeTls(a);}
        op[257] = getOpcodeRep((char)2, (char)2, 258);
        op[258] = getOpcodeRnm(57, 397); // DIGIT
        {int[] a = {260,261,262}; op[259] = getOpcodeCat(a);}
        {char[] a = {50}; op[260] = getOpcodeTls(a);}
        op[261] = getOpcodeTrg((char)48, (char)52);
        op[262] = getOpcodeRnm(57, 397); // DIGIT
        {int[] a = {264,265}; op[263] = getOpcodeCat(a);}
        {char[] a = {50,53}; op[264] = getOpcodeTls(a);}
        op[265] = getOpcodeTrg((char)48, (char)53);
        op[266] = getOpcodeRep((char)0, Character.MAX_VALUE, 267);
        {int[] a = {268,269,270}; op[267] = getOpcodeAlt(a);}
        op[268] = getOpcodeRnm(38, 316); // unreserved
        op[269] = getOpcodeRnm(37, 312); // pct-encoded
        op[270] = getOpcodeRnm(41, 334); // sub-delims
        op[271] = getOpcodeRep((char)0, Character.MAX_VALUE, 272);
        {int[] a = {273,274}; op[272] = getOpcodeCat(a);}
        {char[] a = {47}; op[273] = getOpcodeTls(a);}
        op[274] = getOpcodeRnm(32, 292); // segment
        {int[] a = {276,277}; op[275] = getOpcodeCat(a);}
        {char[] a = {47}; op[276] = getOpcodeTls(a);}
        op[277] = getOpcodeRep((char)0, (char)1, 278);
        {int[] a = {279,280}; op[278] = getOpcodeCat(a);}
        op[279] = getOpcodeRnm(33, 294); // segment-nz
        op[280] = getOpcodeRep((char)0, Character.MAX_VALUE, 281);
        {int[] a = {282,283}; op[281] = getOpcodeCat(a);}
        {char[] a = {47}; op[282] = getOpcodeTls(a);}
        op[283] = getOpcodeRnm(32, 292); // segment
        {int[] a = {285,286}; op[284] = getOpcodeCat(a);}
        op[285] = getOpcodeRnm(33, 294); // segment-nz
        op[286] = getOpcodeRep((char)0, Character.MAX_VALUE, 287);
        {int[] a = {288,289}; op[287] = getOpcodeCat(a);}
        {char[] a = {47}; op[288] = getOpcodeTls(a);}
        op[289] = getOpcodeRnm(32, 292); // segment
        op[290] = getOpcodeRep((char)0, (char)0, 291);
        op[291] = getOpcodeRnm(34, 296); // pchar
        op[292] = getOpcodeRep((char)0, Character.MAX_VALUE, 293);
        op[293] = getOpcodeRnm(34, 296); // pchar
        op[294] = getOpcodeRep((char)1, Character.MAX_VALUE, 295);
        op[295] = getOpcodeRnm(34, 296); // pchar
        {int[] a = {297,298,299,300,301}; op[296] = getOpcodeAlt(a);}
        op[297] = getOpcodeRnm(38, 316); // unreserved
        op[298] = getOpcodeRnm(37, 312); // pct-encoded
        op[299] = getOpcodeRnm(41, 334); // sub-delims
        {char[] a = {58}; op[300] = getOpcodeTls(a);}
        {char[] a = {64}; op[301] = getOpcodeTls(a);}
        op[302] = getOpcodeRep((char)0, Character.MAX_VALUE, 303);
        {int[] a = {304,305,306}; op[303] = getOpcodeAlt(a);}
        op[304] = getOpcodeRnm(34, 296); // pchar
        {char[] a = {47}; op[305] = getOpcodeTls(a);}
        {char[] a = {63}; op[306] = getOpcodeTls(a);}
        op[307] = getOpcodeRep((char)0, Character.MAX_VALUE, 308);
        {int[] a = {309,310,311}; op[308] = getOpcodeAlt(a);}
        op[309] = getOpcodeRnm(34, 296); // pchar
        {char[] a = {47}; op[310] = getOpcodeTls(a);}
        {char[] a = {63}; op[311] = getOpcodeTls(a);}
        {int[] a = {313,314,315}; op[312] = getOpcodeCat(a);}
        {char[] a = {37}; op[313] = getOpcodeTls(a);}
        op[314] = getOpcodeRnm(58, 398); // HEXDIG
        op[315] = getOpcodeRnm(58, 398); // HEXDIG
        {int[] a = {317,318,319,320,321,322}; op[316] = getOpcodeAlt(a);}
        op[317] = getOpcodeRnm(55, 393); // ALPHA
        op[318] = getOpcodeRnm(57, 397); // DIGIT
        {char[] a = {45}; op[319] = getOpcodeTls(a);}
        {char[] a = {46}; op[320] = getOpcodeTls(a);}
        {char[] a = {95}; op[321] = getOpcodeTls(a);}
        {char[] a = {126}; op[322] = getOpcodeTls(a);}
        {int[] a = {324,325}; op[323] = getOpcodeAlt(a);}
        op[324] = getOpcodeRnm(40, 326); // gen-delims
        op[325] = getOpcodeRnm(41, 334); // sub-delims
        {int[] a = {327,328,329,330,331,332,333}; op[326] = getOpcodeAlt(a);}
        {char[] a = {58}; op[327] = getOpcodeTls(a);}
        {char[] a = {47}; op[328] = getOpcodeTls(a);}
        {char[] a = {63}; op[329] = getOpcodeTls(a);}
        {char[] a = {35}; op[330] = getOpcodeTls(a);}
        {char[] a = {91}; op[331] = getOpcodeTls(a);}
        {char[] a = {93}; op[332] = getOpcodeTls(a);}
        {char[] a = {64}; op[333] = getOpcodeTls(a);}
        {int[] a = {335,336,337,338,339,340,341,342,343,344,345}; op[334] = getOpcodeAlt(a);}
        {char[] a = {33}; op[335] = getOpcodeTls(a);}
        {char[] a = {36}; op[336] = getOpcodeTls(a);}
        {char[] a = {38}; op[337] = getOpcodeTls(a);}
        {char[] a = {39}; op[338] = getOpcodeTls(a);}
        {char[] a = {40}; op[339] = getOpcodeTls(a);}
        {char[] a = {41}; op[340] = getOpcodeTls(a);}
        {char[] a = {42}; op[341] = getOpcodeTls(a);}
        {char[] a = {43}; op[342] = getOpcodeTls(a);}
        {char[] a = {44}; op[343] = getOpcodeTls(a);}
        {char[] a = {59}; op[344] = getOpcodeTls(a);}
        {char[] a = {61}; op[345] = getOpcodeTls(a);}
        op[346] = getOpcodeRep((char)4, (char)4, 347);
        op[347] = getOpcodeRnm(57, 397); // DIGIT
        op[348] = getOpcodeRep((char)2, (char)2, 349);
        op[349] = getOpcodeRnm(57, 397); // DIGIT
        op[350] = getOpcodeRep((char)2, (char)2, 351);
        op[351] = getOpcodeRnm(57, 397); // DIGIT
        op[352] = getOpcodeRep((char)2, (char)2, 353);
        op[353] = getOpcodeRnm(57, 397); // DIGIT
        op[354] = getOpcodeRep((char)2, (char)2, 355);
        op[355] = getOpcodeRnm(57, 397); // DIGIT
        op[356] = getOpcodeRep((char)2, (char)2, 357);
        op[357] = getOpcodeRnm(57, 397); // DIGIT
        {int[] a = {359,360}; op[358] = getOpcodeCat(a);}
        {char[] a = {46}; op[359] = getOpcodeTls(a);}
        op[360] = getOpcodeRep((char)1, Character.MAX_VALUE, 361);
        op[361] = getOpcodeRnm(57, 397); // DIGIT
        {int[] a = {363,366,367,368}; op[362] = getOpcodeCat(a);}
        {int[] a = {364,365}; op[363] = getOpcodeAlt(a);}
        {char[] a = {43}; op[364] = getOpcodeTls(a);}
        {char[] a = {45}; op[365] = getOpcodeTls(a);}
        op[366] = getOpcodeRnm(45, 352); // time-hour
        {char[] a = {58}; op[367] = getOpcodeTls(a);}
        op[368] = getOpcodeRnm(46, 354); // time-minute
        {int[] a = {370,371}; op[369] = getOpcodeAlt(a);}
        {char[] a = {90}; op[370] = getOpcodeTls(a);}
        op[371] = getOpcodeRnm(49, 362); // time-numoffset
        {int[] a = {373,374,375,376,377,378}; op[372] = getOpcodeCat(a);}
        op[373] = getOpcodeRnm(45, 352); // time-hour
        {char[] a = {58}; op[374] = getOpcodeTls(a);}
        op[375] = getOpcodeRnm(46, 354); // time-minute
        {char[] a = {58}; op[376] = getOpcodeTls(a);}
        op[377] = getOpcodeRnm(47, 356); // time-second
        op[378] = getOpcodeRep((char)0, (char)1, 379);
        op[379] = getOpcodeRnm(48, 358); // time-secfrac
        {int[] a = {381,382,383,384,385}; op[380] = getOpcodeCat(a);}
        op[381] = getOpcodeRnm(42, 346); // date-fullyear
        {char[] a = {45}; op[382] = getOpcodeTls(a);}
        op[383] = getOpcodeRnm(43, 348); // date-month
        {char[] a = {45}; op[384] = getOpcodeTls(a);}
        op[385] = getOpcodeRnm(44, 350); // date-mday
        {int[] a = {387,388}; op[386] = getOpcodeCat(a);}
        op[387] = getOpcodeRnm(51, 372); // partial-time
        op[388] = getOpcodeRnm(50, 369); // time-offset
        {int[] a = {390,391,392}; op[389] = getOpcodeCat(a);}
        op[390] = getOpcodeRnm(52, 380); // full-date
        {char[] a = {84}; op[391] = getOpcodeTls(a);}
        op[392] = getOpcodeRnm(53, 386); // full-time
        {int[] a = {394,395}; op[393] = getOpcodeAlt(a);}
        op[394] = getOpcodeTrg((char)65, (char)90);
        op[395] = getOpcodeTrg((char)97, (char)122);
        {char[] a = {10}; op[396] = getOpcodeTbs(a);}
        op[397] = getOpcodeTrg((char)48, (char)57);
        {int[] a = {399,400,401,402,403,404,405}; op[398] = getOpcodeAlt(a);}
        op[399] = getOpcodeRnm(57, 397); // DIGIT
        {char[] a = {65}; op[400] = getOpcodeTls(a);}
        {char[] a = {66}; op[401] = getOpcodeTls(a);}
        {char[] a = {67}; op[402] = getOpcodeTls(a);}
        {char[] a = {68}; op[403] = getOpcodeTls(a);}
        {char[] a = {69}; op[404] = getOpcodeTls(a);}
        {char[] a = {70}; op[405] = getOpcodeTls(a);}
    }

    public static void display(PrintStream out) {
        out.println(";");
        out.println("; apg.SiweGrammar");
        out.println(";");
        out.println("sign-in-with-ethereum =");
        out.println("    domain %s\" wants you to sign in with your Ethereum account:\" LF");
        out.println("    address LF");
        out.println("    LF");
        out.println("    [ statement LF ]");
        out.println("    LF");
        out.println("    %s\"URI: \" URI LF");
        out.println("    %s\"Version: \" version LF");
        out.println("    %s\"Chain ID: \" chain-id LF");
        out.println("    %s\"Nonce: \" nonce LF");
        out.println("    %s\"Issued At: \" issued-at");
        out.println("    [ LF %s\"Expiration Time: \" expiration-time ]");
        out.println("    [ LF %s\"Not Before: \" not-before ]");
        out.println("    [ LF %s\"Request ID: \" request-id ]");
        out.println("    [ LF %s\"Resources:\"");
        out.println("    resources ]");
        out.println("domain = authority");
        out.println("address = \"0x\" 40*40HEXDIG");
        out.println("    ; Must also conform to captilization");
        out.println("    ; checksum encoding specified in EIP-55");
        out.println("    ; where applicable (EOAs).");
        out.println("statement = 1*( reserved / unreserved / \" \" )");
        out.println("    ; The purpose is to exclude LF (line breaks).");
        out.println("version = \"1\"");
        out.println("nonce = 8*( ALPHA / DIGIT )");
        out.println("issued-at = date-time");
        out.println("expiration-time = date-time");
        out.println("not-before = date-time");
        out.println("request-id = *pchar");
        out.println("chain-id = 1*DIGIT");
        out.println("    ; See EIP-155 for valid CHAIN_IDs.");
        out.println("resources = *( LF resource )");
        out.println("resource = \"- \" URI");
        out.println("; ------------------------------------------------------------------------------");
        out.println("; RFC 3986");
        out.println("URI           = scheme \":\" hier-part [ \"?\" query ] [ \"#\" fragment ]");
        out.println("hier-part     = \"//\" authority path-abempty");
        out.println("              / path-absolute");
        out.println("              / path-rootless");
        out.println("              / path-empty");
        out.println("scheme        = ALPHA *( ALPHA / DIGIT / \"+\" / \"-\" / \".\" )");
        out.println("authority     = [ userinfo \"@\" ] host [ \":\" port ]");
        out.println("userinfo      = *( unreserved / pct-encoded / sub-delims / \":\" )");
        out.println("host          = IP-literal / IPv4address / reg-name");
        out.println("port          = *DIGIT");
        out.println("IP-literal    = \"[\" ( IPv6address / IPvFuture  ) \"]\"");
        out.println("IPvFuture     = \"v\" 1*HEXDIG \".\" 1*( unreserved / sub-delims / \":\" )");
        out.println("IPv6address   =                            6( h16 \":\" ) ls32");
        out.println("              /                       \"::\" 5( h16 \":\" ) ls32");
        out.println("              / [               h16 ] \"::\" 4( h16 \":\" ) ls32");
        out.println("              / [ *1( h16 \":\" ) h16 ] \"::\" 3( h16 \":\" ) ls32");
        out.println("              / [ *2( h16 \":\" ) h16 ] \"::\" 2( h16 \":\" ) ls32");
        out.println("              / [ *3( h16 \":\" ) h16 ] \"::\"    h16 \":\"   ls32");
        out.println("              / [ *4( h16 \":\" ) h16 ] \"::\"              ls32");
        out.println("              / [ *5( h16 \":\" ) h16 ] \"::\"              h16");
        out.println("              / [ *6( h16 \":\" ) h16 ] \"::\"");
        out.println("h16           = 1*4HEXDIG");
        out.println("ls32          = ( h16 \":\" h16 ) / IPv4address");
        out.println("IPv4address   = dec-octet \".\" dec-octet \".\" dec-octet \".\" dec-octet");
        out.println("dec-octet     = DIGIT                 ; 0-9");
        out.println("                 / %x31-39 DIGIT         ; 10-99");
        out.println("                 / \"1\" 2DIGIT            ; 100-199");
        out.println("                 / \"2\" %x30-34 DIGIT     ; 200-249");
        out.println("                 / \"25\" %x30-35          ; 250-255");
        out.println("reg-name      = *( unreserved / pct-encoded / sub-delims )");
        out.println("path-abempty  = *( \"/\" segment )");
        out.println("path-absolute = \"/\" [ segment-nz *( \"/\" segment ) ]");
        out.println("path-rootless = segment-nz *( \"/\" segment )");
        out.println("path-empty    = 0pchar");
        out.println("segment       = *pchar");
        out.println("segment-nz    = 1*pchar");
        out.println("pchar         = unreserved / pct-encoded / sub-delims / \":\" / \"@\"");
        out.println("query         = *( pchar / \"/\" / \"?\" )");
        out.println("fragment      = *( pchar / \"/\" / \"?\" )");
        out.println("pct-encoded   = \"%\" HEXDIG HEXDIG");
        out.println("unreserved    = ALPHA / DIGIT / \"-\" / \".\" / \"_\" / \"~\"");
        out.println("reserved      = gen-delims / sub-delims");
        out.println("gen-delims    = \":\" / \"/\" / \"?\" / \"#\" / \"[\" / \"]\" / \"@\"");
        out.println("sub-delims    = \"!\" / \"$\" / \"&\" / \"'\" / \"(\" / \")\"");
        out.println("              / \"*\" / \"+\" / \",\" / \";\" / \"=\"");
        out.println("; ------------------------------------------------------------------------------");
        out.println("; RFC 3339");
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
        out.println("partial-time    = time-hour \":\" time-minute \":\" time-second");
        out.println("                  [time-secfrac]");
        out.println("full-date       = date-fullyear \"-\" date-month \"-\" date-mday");
        out.println("full-time       = partial-time time-offset");
        out.println("date-time       = full-date \"T\" full-time");
        out.println("; ------------------------------------------------------------------------------");
        out.println("; RFC 5234");
        out.println("ALPHA          =  %x41-5A / %x61-7A   ; A-Z / a-z");
        out.println("LF             =  %x0A");
        out.println("                  ; linefeed");
        out.println("DIGIT          =  %x30-39");
        out.println("                  ; 0-9");
        out.println("HEXDIG         =  DIGIT / \"A\" / \"B\" / \"C\" / \"D\" / \"E\" / \"F\"");
    }

}
