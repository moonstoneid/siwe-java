package org.mn.web3login.siwe;

import java.time.OffsetDateTime;
import java.util.Arrays;

import apg.Ast;
import apg.Utilities;
import lombok.Getter;
import org.mn.web3login.siwe.error.ErrorTypes;
import org.mn.web3login.siwe.error.SiweException;
import org.mn.web3login.siwe.grammar.SiweGrammar;
import org.mn.web3login.siwe.util.Utils;
import org.mn.web3login.siwe.validator.SignatureValidator;
import org.mn.web3login.siwe.util.ValidatorUtils;
import org.web3j.protocol.Web3j;

/**
 * Creates a new SiweMessage<.br>
 * <br>
 * A new instance can be created with {@link Builder} or with {@link Parser}.
 */
@Getter
public class SiweMessage {

    /**
     * RFC 4501 dns authority that is requesting the signing.
     */
    private String domain;

    /**
     * Ethereum address that requested the signing in EIP-55 format.
     */
    private String address;

    /**
     * Optional human-readable ASCII assertion that the user will sign, and it must not contain `\n`.
     */
    private String statement;

    /**
     * RFC 3986 URI referring to the resource that is the subject of the signing (as in the
     * __subject__ of a claim).
     */
    private String uri;

    /**
     * Current version of the message.
     */
    private String version;

    /**
     * EIP-155 Chain ID to which the session is bound, and the network where Contract Accounts must
     * be resolved.
     */
    private int chainId;

    /**
     * Randomized token used to prevent replay attacks, at least 8 alphanumeric characters.
     */
    private String nonce;

    /**
     * ISO 8601 datetime string of the current time.
     */
    private String issuedAt;

    /**
     * Optional ISO 8601 datetime string that, if present, indicates when the signed authentication
     * message is no longer valid.
     */
    private String expirationTime;

    /**
     * Optional ISO 8601 datetime string that, if present, indicates when the signed authentication
     * message will become valid.
     */
    private String notBefore;

    /**
     * Optional system-specific identifier that may be used to uniquely refer to the sign-in request.
     */
    private String requestId;

    /**
     * List of information or references to information the user wishes to have resolved as part of
     * authentication by the relying party. They are expressed as RFC 3986 URIs separated by `\n- `.
     */
    private String[] resources;

    /**
     * Private default constructor. A new instance can be created with {@link Builder} or
     * {@link Parser}.
     */
    private SiweMessage() {

    }

    /**
     * Verifies the integrity of the fields of this object by checking several fields and the
     * validity of the signature.
     *
     * @param domain    RFC 4501 dns authority that is requesting the signing
     * @param nonce     The nonce issued by the backend
     * @param signature A valid signature for this message
     *
     * @throws SiweException if the signature is invalid or if fields ar missing
     */
    public void verify(String domain, String nonce, String signature) throws SiweException {
        verify(domain, nonce, signature, null);
    }

    /**
     * Verifies the integrity of the fields of this object by checking several fields and the
     * validity of the signature.
     *
     * @param domain    RFC 4501 dns authority that is requesting the signing
     * @param nonce     The nonce issued by the backend
     * @param signature A valid signature for this message
     * @param provider  A {@link Web3j} provider instance to conduct EIP-1271 signature check
     *
     * @throws SiweException if the signature is invalid or if fields ar missing
     */
    public void verify(String domain, String nonce, String signature, Web3j provider) throws SiweException {
        // Verify that the given domain matches the domain of this object
        if (domain == null || domain.isEmpty() || !domain.equals(this.domain)) {
            throw new SiweException("Domain does not match.", ErrorTypes.DOMAIN_MISMATCH);
        }

        // Verify that the given nonce matches the nonce of this object
        if (nonce == null || nonce.isEmpty() || !nonce.equals(this.nonce)) {
            throw new SiweException("Nonce does not match.", ErrorTypes.NONCE_MISMATCH);
        }

        long now = OffsetDateTime.now().toEpochSecond();

        // Verify that the message is not yet expired
        if (expirationTime != null) {
            long exp = OffsetDateTime.parse(expirationTime).toEpochSecond();
            if (now >= exp) {
                throw new SiweException("Message expired on " + expirationTime + ".",
                        ErrorTypes.EXPIRED_MESSAGE);
            }
        }

        // Verify that the message is already valid
        if (notBefore != null) {
            long nbfr = OffsetDateTime.parse(notBefore).toEpochSecond();
            if (now < nbfr) {
                throw new SiweException("Message is not valid before " + notBefore + ".",
                        ErrorTypes.NOT_YET_VALID_MESSAGE);
            }
        }

        // Verify signature
        if (!SignatureValidator.isValidSignature(this, signature, provider)) {
            throw new SiweException("Invalid signature.", ErrorTypes.INVALID_SIGNATURE);
        }
    }

    /**
     * Validates if the values of this object are present and in the correct format. Does not verify
     * the correctness of these values.
     *
     * @throws SiweException if a field is invalid
     */
    private void validateMessage() throws SiweException {
        // Check domain
        if (domain == null || domain.isEmpty()) {
            throw new SiweException("Domain is invalid.", ErrorTypes.INVALID_DOMAIN);
        }

        // Check if address conforms to EIP-55 (address checksum)
        if (address == null || address.isEmpty() || !ValidatorUtils.isEIP55Address(address)) {
            throw new SiweException("Address does not conform to EIP-55.", ErrorTypes.INVALID_ADDRESS);
        }

        // Check statement
        if (statement == null) {
            throw new SiweException("Statement is invalid.", ErrorTypes.INVALID_STATEMENT);
        }

        // Check URI
        if (uri == null || uri.isEmpty() || !ValidatorUtils.isURI(uri)) {
            throw new SiweException("URI is not a valid URI.", ErrorTypes.INVALID_URI);
        }

        // Check if version is 1
        if (version == null || !version.equals("1")) {
            throw new SiweException("Version must be 1.", ErrorTypes.INVALID_MESSAGE_VERSION);
        }

        // Check if nonce is alphanumeric and
        if (nonce == null || !nonce.matches("[a-zA-Z0-9]{8,}")) {
            throw new SiweException("Nonce is not alphanumeric or shorter than 8 chars.",
                    ErrorTypes.INVALID_NONCE);
        }

        // Check issuedAt
        if (issuedAt == null || !ValidatorUtils.isISO860Format(issuedAt)) {
            throw new SiweException("IssuedAt does not conform to ISO-8601.",
                    ErrorTypes.INVALID_TIME_FORMAT);
        }

        // Check if optional field expirationTime is present and has valid format
        if (expirationTime != null && !ValidatorUtils.isISO860Format(expirationTime)) {
            throw new SiweException("ExpirationTime does not conform to ISO-8601.",
                    ErrorTypes.INVALID_TIME_FORMAT);
        }

        // Check if optional field notBefore is present and has valid format
        if (notBefore != null && !ValidatorUtils.isISO860Format(notBefore)) {
            throw new SiweException("NotBefore does not conform to ISO-8601.",
                    ErrorTypes.INVALID_TIME_FORMAT);
        }

        // Check if optional field resources is present, not empty and has valid URI format
        if (resources != null && resources.length > 0) {
            for (String uri : resources) {
                if (!ValidatorUtils.isURI(uri)) {
                    throw new SiweException("Resources contains an invalid URI.",
                            ErrorTypes.INVALID_RESOURCES);
                }
            }
        }
    }

    /**
     * This method parses all the fields in the object and returns a valid EIP-4361 string.
     *
     * @return a valid EIP-4361 string
     */
    public String toMessage() {
        String message;

        // The switch becomes relevant once there are more than one version
        switch (version) {
            case "1": {
                message = toMessageV1();
                break;
            }
            default: {
                message = toMessageV1();
                break;
            }
        }
        return message;
    }

    /**
     * This method parses all the fields in the object and returns a valid EIP-4361 string.
     *
     * @return a valid EIP-4361 string
     */
    private String toMessageV1() {
        StringBuilder sb = new StringBuilder();

        sb.append(domain).append(" wants you to sign in with your Ethereum account:").append("\n");

        sb.append(address).append("\n\n");

        sb.append(statement);
        if (statement != null) {
            sb.append("\n");
        }

        sb.append("\n").append("URI: ").append(uri);
        sb.append("\n").append("Version: ").append(version);
        sb.append("\n").append("Chain ID: ").append(chainId);

        if (nonce == null) {
            nonce = Utils.generateNonce();
        }
        sb.append("\n").append("Nonce: ").append(nonce);

        if (issuedAt == null) {
            issuedAt = OffsetDateTime.now().toString();
        }
        sb.append("\n").append("Issued At: ").append(issuedAt);

        if (expirationTime != null) {
            sb.append("\n").append("Expiration Time: ").append(expirationTime);
        }

        if (notBefore != null) {
            sb.append("\n").append("Not Before: ").append(notBefore);
        }

        if (requestId != null) {
            sb.append("\n").append("Request ID: ").append(requestId);
        }

        if (resources != null) {
            sb.append("\n").append("Resources:");
            for (String res : resources) {
                sb.append("\n- ").append(res);
            }
        }

        return sb.toString();
    }

    /**
     * This builder creates new instances of {@link SiweMessage}.
     */
    public static class Builder {

        private final SiweMessage siweMessage;

        /**
         * Constructs a new builder.
         *
         * @param domain   RFC 4501 dns authority that is requesting the signing
         * @param address  Ethereum address performing the signing
         * @param uri      RFC 3986 URI referring to the resource that is the subject of the signing
         * @param version  Current version of the message
         * @param chainId  EIP-155 Chain ID to which the session is bound
         * @param nonce    Randomized token used to prevent replay attacks
         * @param issuedAt ISO 8601 datetime string of the current time
         */
        public Builder(String domain, String address, String uri, String version, int chainId,
                String nonce, String issuedAt) {
            siweMessage = new SiweMessage();
            siweMessage.domain = domain;
            siweMessage.address = address;
            siweMessage.uri = uri;
            siweMessage.version = version;
            siweMessage.chainId = chainId;
            siweMessage.nonce = nonce;
            siweMessage.issuedAt = issuedAt;
        }

        /**
         * Sets a human-readable ASCII assertion that the user will sign. Must not contain '\n'.
         *
         * @param statement The statement
         *
         * @return a reference to this object
         */
        public Builder statement(String statement) {
            siweMessage.statement = statement;
            return this;
        }

        /**
         * Sets a ISO 8601 datetime string that indicates when the signed authentication message is
         * no longer valid.
         *
         * @param expirationTime The ISO 8601 datetime string
         *
         * @return a reference to this object
         */
        public Builder expirationTime(String expirationTime) {
            siweMessage.expirationTime = expirationTime;
            return this;
        }

        /**
         * Sets a ISO 8601 datetime string that indicates when the signed authentication message
         * will become valid.
         *
         * @param notBefore The ISO 8601 datetime string
         *
         * @return a reference to this object
         */
        public Builder notBefore(String notBefore) {
            siweMessage.notBefore = notBefore;
            return this;
        }

        /**
         * Sets a requestId that may be used to uniquely refer to the sign-in request.
         *
         * @param requestId The requestId
         *
         * @return a reference to this object
         */
        public Builder requestId(String requestId) {
            siweMessage.requestId = requestId;
            return this;
        }

        /**
         * Sets an array of resources
         *
         * @param resources The resources
         *
         * @return a reference to this object
         */
        public Builder resources(String[] resources) {
            siweMessage.resources = resources;
            return this;
        }

        /**
         * Creates a new {@link SiweMessage} instance with the supplied configuration.
         *
         * @return a new {@link SiweMessage} instance
         *
         * @throws SiweException if a field is invalid
         */
        public SiweMessage build() throws SiweException {
            // After all fields are set, check if all mandatory fields are present and in the
            // correct format.
            siweMessage.validateMessage();
            return siweMessage;
        }

    }

    /**
     * An ABNF (Augmented Backus-Naur Form) parser for EIP-4361 strings.
     */
    public static class Parser {

        private String domain;
        private String address;
        private String statement;
        private String uri;
        private String version;
        private int chainId;
        private String nonce;
        private String issuedAt;
        private String expirationTime;
        private String notBefore;
        private String requestId;
        private String[] resources;

        public Parser() {

        }

        /**
         * Tries to parse the given string. The given string must be an EIP-4361 formatted message,
         * otherwise an exception is thrown.
         *
         * @param msg A valid EIP-4361 message
         *
         * @throws SiweException if the parsing fails
         */
        public SiweMessage parse(String msg) throws SiweException {
            apg.Parser parser = new apg.Parser(SiweGrammar.getInstance());
            parser.setStartRule(SiweGrammar.RuleNames.SIGN_IN_WITH_ETHEREUM.ruleID());
            parser.setInputString(msg);

            Ast ast = parser.enableAst(true);

            apg.Parser.Result parseResult;
            try {
                ast.enableRuleNode(SiweGrammar.RuleNames.SIGN_IN_WITH_ETHEREUM.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.DOMAIN.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.ADDRESS.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.STATEMENT.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.URI.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.VERSION.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.NONCE.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.ISSUED_AT.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.EXPIRATION_TIME.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.NOT_BEFORE.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.REQUEST_ID.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.CHAIN_ID.ruleID(), true);
                ast.enableRuleNode(SiweGrammar.RuleNames.RESOURCES.ruleID(), true);
                parseResult = parser.parse();
            } catch (Exception e) {
                throw new SiweException("ABNF parsing failed.", ErrorTypes.UNABLE_TO_PARSE);
            }
            if (!parseResult.success()) {
                throw new SiweException("ABNF parsing failed.", ErrorTypes.UNABLE_TO_PARSE);
            }

            try {
                ast.setRuleCallback(SiweGrammar.RuleNames.DOMAIN.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.DOMAIN.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.ADDRESS.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.ADDRESS.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.STATEMENT.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.STATEMENT.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.URI.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.URI.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.VERSION.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.VERSION.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.NONCE.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.NONCE.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.ISSUED_AT.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.ISSUED_AT.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.EXPIRATION_TIME.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.EXPIRATION_TIME.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.NOT_BEFORE.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.NOT_BEFORE.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.REQUEST_ID.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.REQUEST_ID.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.CHAIN_ID.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.CHAIN_ID.ruleEnumName()));
                ast.setRuleCallback(SiweGrammar.RuleNames.RESOURCES.ruleID(), new AstTranslator(ast,
                        SiweGrammar.RuleNames.RESOURCES.ruleEnumName()));
                ast.translateAst();
            } catch (Exception e) {
                throw new SiweException("Id out of range. Parsing failed.", ErrorTypes.UNABLE_TO_PARSE);
            }

            SiweMessage siweMessage = new SiweMessage();
            siweMessage.domain = domain;
            siweMessage.address = address;
            siweMessage.statement = statement;
            siweMessage.uri = uri;
            siweMessage.version = version;
            siweMessage.chainId = chainId;
            siweMessage.nonce = nonce;
            siweMessage.issuedAt = issuedAt;
            siweMessage.expirationTime = expirationTime;
            siweMessage.notBefore = notBefore;
            siweMessage.requestId = requestId;
            siweMessage.resources = resources;

            // After all fields are set, check if all mandatory fields are present and in the
            // correct format
            siweMessage.validateMessage();

            return siweMessage;
        }

        private class AstTranslator extends Ast.AstCallback {

            private final String nodeName;

            private AstTranslator(Ast ast, String nodeName) {
                super(ast);
                this.nodeName = nodeName;
            }

            @Override
            public boolean preBranch(int offset, int length) {
                String input = new String(callbackData.inputString);
                String substring = input.substring(offset, offset + length);
                int maxLength = substring.length();

                String value = Utilities.charArrayToString(callbackData.inputString, offset, length,
                        maxLength);
                switch (SiweGrammar.RuleNames.valueOf(nodeName)) {
                    case DOMAIN:
                        domain = value;
                        break;
                    case ADDRESS:
                        address = value;
                        break;
                    case STATEMENT:
                        statement = value;
                        break;
                    case URI:
                        uri = value;
                        break;
                    case VERSION:
                        version = value;
                        break;
                    case NONCE:
                        nonce = value;
                        break;
                    case ISSUED_AT:
                        issuedAt = value;
                        break;
                    case EXPIRATION_TIME:
                        expirationTime = value;
                        break;
                    case NOT_BEFORE:
                        notBefore = value;
                        break;
                    case REQUEST_ID:
                        requestId = value;
                        break;
                    case CHAIN_ID:
                        chainId = Integer.parseInt(value);
                        break;
                    case RESOURCES:
                        // Split resources by \n and remove "- " at the beginning
                        resources = Arrays.stream(substring.split("\n"))
                                .filter(x -> !x.isEmpty())
                                .map(s -> s.replace("- ", ""))
                                .toArray(String[]::new);
                        break;
                    default:
                        break;
                }
                return true;
            }

            @Override
            public void postBranch(int offset, int length) {

            }

        }

    }

}
