import {isValidPocketAddress, ParsedMessage} from "../parser";
import {
    base64ToBytes,
    bech32ify,
    generateNonce,
    getAddressFromPublicKey,
    isValidISO8601Date
} from "./utils";
import {SiwpError, SiwpErrorType, SiwpResponse, VerifyAdr36Params, VerifyERC4361Params, VerifyOpts} from "./types";
import * as uri from 'valid-url';
import * as etc from '@noble/curves/abstract/utils';
import {secp256k1} from '@noble/curves/secp256k1'
import {sha256} from '@noble/hashes/sha256';
import {ripemd160} from "@noble/hashes/ripemd160";
import { StdSignDoc, serializeSignDoc } from "@cosmjs/amino";

export class SiwpMessage {
    /**RFC 3986 URI scheme for the authority that is requesting the signing. */
    scheme?: string;
    /**RFC 4501 dns authority that is requesting the signing. */
    domain: string;
    /**Ethereum address performing the signing conformant to capitalization
     * encoded checksum specified in EIP-55 where applicable. */
    address: string;
    /**Human-readable ASCII assertion that the user will sign, and it must not
     * contain `\n`. */
    statement?: string;
    /**RFC 3986 URI referring to the resource that is the subject of the signing
     *  (as in the __subject__ of a claim). */
    uri: string;
    /**Current version of the message. */
    version: string;
    /**EIP-155 Chain ID to which the session is bound, and the network where
     * Contract Accounts must be resolved. */
    chainId: string | "mainnet" | "testnet";
    /**Randomized token used to prevent replay attacks, at least 8 alphanumeric
     * characters. */
    nonce: string;
    /**ISO 8601 datetime string of the current time. */
    issuedAt?: string;
    /**ISO 8601 datetime string that, if present, indicates when the signed
     * authentication message is no longer valid. */
    expirationTime?: string;
    /**ISO 8601 datetime string that, if present, indicates when the signed
     * authentication message will become valid. */
    notBefore?: string;
    /**System-specific identifier that may be used to uniquely refer to the
     * sign-in request. */
    requestId?: string;
    /**List of information or references to information the user wishes to have
     * resolved as part of authentication by the relying party. They are
     * expressed as RFC 3986 URIs separated by `\n- `. */
    resources?: Array<string>;

    constructor(param: string | Partial<SiwpMessage>) {
        if (typeof param === 'string') {
            try {
                const parsedMessage = new ParsedMessage(param);
                this.scheme = parsedMessage.scheme;
                this.domain = parsedMessage.domain;
                this.address = parsedMessage.address;
                this.statement = parsedMessage.statement;
                this.uri = parsedMessage.uri;
                this.version = parsedMessage.version;
                this.nonce = parsedMessage.nonce;
                this.issuedAt = parsedMessage.issuedAt;
                this.expirationTime = parsedMessage.expirationTime;
                this.notBefore = parsedMessage.notBefore;
                this.requestId = parsedMessage.requestId;
                this.chainId = parsedMessage.chainId;
                this.resources = parsedMessage.resources;
            } catch (e) {
                throw new SiwpError(SiwpErrorType.UNABLE_TO_PARSE, `SiwpMessage`, param);
            }
        } else {
            this.scheme = param.scheme;
            this.domain = param.domain!;
            this.address = param.address!;
            this.statement = param.statement;
            this.uri = param.uri!;
            this.version = param.version!;
            this.chainId = param.chainId!;
            this.nonce = param.nonce!;
            this.issuedAt = param?.issuedAt;
            this.expirationTime = param.expirationTime;
            this.notBefore = param.notBefore;
            this.requestId = param.requestId;
            this.resources = param.resources;
        }
        this.nonce = this.nonce || generateNonce();
        this.validateMessage();
    }

    /**
     * Validates the values of this object fields.
     * @throws Throws an {ErrorType} if a field is invalid.
     */
    private validateMessage() {
        /** `domain` check. */
        if (
            !this.domain ||
            this.domain.length === 0 ||
            !/[^#?]*/.test(this.domain)
        ) {
            throw new SiwpError(
                SiwpErrorType.INVALID_DOMAIN,
                `${this.domain} to be a valid domain.`
            );
        }

        /** EIP-55 `address` check. */
        if (!isValidPocketAddress(this.address)) {
            throw new SiwpError(
                SiwpErrorType.INVALID_ADDRESS,
                `${this.address} to be a valid Pocket Network address.`
            );
        }

        /** Check if the URI is valid. */
        if (!uri.isUri(this.uri)) {
            throw new SiwpError(
                SiwpErrorType.INVALID_URI,
                `${this.uri} to be a valid uri.`
            );
        }

        /** Check if the version is 1. */
        if (this.version !== '1') {
            throw new SiwpError(
                SiwpErrorType.INVALID_MESSAGE_VERSION,
                '1',
                this.version
            );
        }

        /** Check if the nonce is alphanumeric and bigger then 8 characters */
        const nonce = this?.nonce?.match(/[a-zA-Z0-9]{8,}/);
        if (!nonce || this.nonce.length < 8 || nonce[0] !== this.nonce) {
            throw new SiwpError(
                SiwpErrorType.INVALID_NONCE,
                `Length > 8 (${nonce?.length}). Alphanumeric.`,
                this.nonce
            );
        }

        /** `issuedAt` conforms to ISO-8601 and is a valid date. */
        if (this.issuedAt) {
            if (!isValidISO8601Date(this.issuedAt)) {
                throw new SiwpError(SiwpErrorType.INVALID_TIME_FORMAT);
            }
        }

        /** `expirationTime` conforms to ISO-8601 and is a valid date. */
        if (this.expirationTime) {
            if (!isValidISO8601Date(this.expirationTime)) {
                throw new SiwpError(SiwpErrorType.INVALID_TIME_FORMAT);
            }
        }

        /** `notBefore` conforms to ISO-8601 and is a valid date. */
        if (this.notBefore) {
            if (!isValidISO8601Date(this.notBefore)) {
                throw new SiwpError(SiwpErrorType.INVALID_TIME_FORMAT);
            }
        }

        /** `chainId` is either pocket or pocket-alpha or pocket-beta. */
        if (!['pocket', 'pocket-alpha', 'pocket-beta'].includes(this.chainId)) {
            throw new SiwpError(
                SiwpErrorType.INVALID_CHAIN_ID,
                'pocket, pocket-alpha or pocket-beta',
                this.chainId
            );
        }
    }

    /**
     * This function can be used to retrieve an EIP-4361 formated message for
     * signature, although you can call it directly it's advised to use
     * [prepareMessage()] instead which will resolve to the correct method based
     * on the [type] attribute of this object, in case of other formats being
     * implemented.
     * @returns {string} EIP-4361 formated message, ready for EIP-191 signing.
     */
    toMessage(): string {
        /** Validates all fields of the object */
        this.validateMessage();
        const headerPrefx = this.scheme ? `${this.scheme}://${this.domain}` : this.domain;
        const header = `${headerPrefx} wants you to sign in with your Pocket account:`;
        const uriField = `URI: ${this.uri}`;
        let prefix = [header, this.address].join('\n');
        const versionField = `Version: ${this.version}`;

        if (!this.nonce) {
            this.nonce = generateNonce();
        }

        const chainField = `Chain ID: ` + this.chainId || 'pocket';

        const nonceField = `Nonce: ${this.nonce}`;

        const suffixArray = [uriField, versionField, chainField, nonceField];

        this.issuedAt = this.issuedAt || new Date().toISOString();

        suffixArray.push(`Issued At: ${this.issuedAt}`);

        if (this.expirationTime) {
            const expiryField = `Expiration Time: ${this.expirationTime}`;

            suffixArray.push(expiryField);
        }

        if (this.notBefore) {
            suffixArray.push(`Not Before: ${this.notBefore}`);
        }

        if (this.requestId) {
            suffixArray.push(`Request ID: ${this.requestId}`);
        }

        if (this.resources) {
            suffixArray.push(
                [`Resources:`, ...this.resources.map(x => `- ${x}`)].join('\n')
            );
        }

        const suffix = suffixArray.join('\n');
        prefix = [prefix, this.statement].join('\n\n');
        if (this.statement) {
            prefix += '\n';
        }
        return [prefix, suffix].join('\n');
    }

    /**
     * This method parses all the fields in the object and creates a messaging for signing
     * message according to the type defined.
     * @returns {string} Returns a message ready to be signed according with the
     * type defined in the object.
     */
    prepareMessage(): string {
        let message: string;
        switch (this.version) {
            case '1': {
                message = this.toMessage();
                break;
            }

            default: {
                message = this.toMessage();
                break;
            }
        }
        return message;
    }

    /**
     * Verifies the integrity of the object by matching its signature.
     * @param params Parameters to verifyERC4361 the integrity of the message, signature is required.
     * @param opts Options for the verification process
     * @returns {Promise<SiwpMessage>} This object if valid.
     */
    async verifyERC4361(
        params: VerifyERC4361Params,
        opts: VerifyOpts = { suppressExceptions: false }
    ): Promise<SiwpResponse> {
        const fail = (response: SiwpResponse) => {
            if (opts.suppressExceptions) {
                return response;
            } else {
                throw response;
            }
        };

        const { signature, publicKey, scheme, domain, nonce, time } = params;

        /** Scheme for domain binding */
        if (scheme && scheme !== this.scheme) {
            return fail({
                success: false,
                data: this,
                error: new SiwpError(
                    SiwpErrorType.SCHEME_MISMATCH,
                    scheme,
                    this.scheme
                ),
            });
        }

        /** Domain binding */
        if (domain && domain !== this.domain) {
            return fail({
                success: false,
                data: this,
                error: new SiwpError(
                    SiwpErrorType.DOMAIN_MISMATCH,
                    domain,
                    this.domain
                ),
            });
        }

        /** Nonce binding */
        if (nonce && nonce !== this.nonce) {
            return fail({
                success: false,
                data: this,
                error: new SiwpError(SiwpErrorType.NONCE_MISMATCH, nonce, this.nonce),
            });
        }

        /** Check time or now */
        const checkTime = new Date(time || new Date());

        /** Message not expired */
        if (this.expirationTime) {
            const expirationDate = new Date(this.expirationTime);
            if (checkTime.getTime() >= expirationDate.getTime()) {
                return fail({
                    success: false,
                    data: this,
                    error: new SiwpError(
                        SiwpErrorType.EXPIRED_MESSAGE,
                        `${checkTime.toISOString()} < ${expirationDate.toISOString()}`,
                        `${checkTime.toISOString()} >= ${expirationDate.toISOString()}`
                    ),
                });
            }
        }

        /** Message is valid already */
        if (this.notBefore) {
            const notBefore = new Date(this.notBefore);
            if (checkTime.getTime() < notBefore.getTime()) {
                return fail({
                    success: false,
                    data: this,
                    error: new SiwpError(
                        SiwpErrorType.NOT_YET_VALID_MESSAGE,
                        `${checkTime.toISOString()} >= ${notBefore.toISOString()}`,
                        `${checkTime.toISOString()} < ${notBefore.toISOString()}`
                    ),
                });
            }
        }

        /** Recover address from signature */
        let addr;

        try {
            addr = await getAddressFromPublicKey(publicKey);
        } catch (e) {
            return fail({
                success: false,
                data: this,
                error: new SiwpError(SiwpErrorType.ADDRESS_UNRECOVERABLE, this.address, addr),
            })
        }

        /** The address recovered from the public key does not match the one in the message */
        if (addr !== this.address) {
            return fail({
                success: false,
                data: this,
                error: new SiwpError(
                    SiwpErrorType.ADDRESS_MISMATCH,
                    this.address,
                    addr
                ),
            });
        }

        let  message;

        try {
            message = this.prepareMessage();
        } catch (e) {
            return fail({
                success: false,
                data: this,
                error: e as SiwpError,
            });
        }

        /** Verify the signature */
        let isValid = false;

        try {
            const messageHash = sha256(new TextEncoder().encode(message));
            isValid = secp256k1.verify(etc.hexToBytes(signature).subarray(0,64), messageHash, etc.hexToBytes(publicKey));
        } catch (e) {
            const message =
                e instanceof Error ? e.message : 'Error during signature verification. Please check the signature.';

            return fail({
                success: false,
                data: this,
                error: new SiwpError(SiwpErrorType.SIGNATURE_VERIFICATION_ERROR, '', message),
            });
        }

        if (!isValid) {
            return fail({
                success: false,
                data: this,
                error: new SiwpError(
                    SiwpErrorType.INVALID_SIGNATURE,
                    `Signature does not match the message and public key.`,
                ),
            });
        }

        return {
            success: true,
            data: this,
        };
    }

    async verifyAdr36(input: VerifyAdr36Params, opts: VerifyOpts = { suppressExceptions: false }): Promise<SiwpResponse> {
        const fail = (response: SiwpResponse) => {
            if (opts.suppressExceptions) {
                return response;
            } else {
                throw response;
            }
        };

        try {
            const {
                domain,
                scheme,
                signature,
                publicKey,
            } = input;

            /** Scheme for domain binding */
            if (scheme && scheme !== this.scheme) {
                return fail({
                    success: false,
                    data: this,
                    error: new SiwpError(
                        SiwpErrorType.SCHEME_MISMATCH,
                        scheme,
                        this.scheme
                    ),
                });
            }

            /** Domain binding */
            if (domain && domain !== this.domain) {
                return fail({
                    success: false,
                    data: this,
                    error: new SiwpError(
                        SiwpErrorType.DOMAIN_MISMATCH,
                        domain,
                        this.domain
                    ),
                });
            }

            /** Check time or now */
            const checkTime = new Date();

            /** Message not expired */
            if (this.expirationTime) {
                const expirationDate = new Date(this.expirationTime);
                if (checkTime.getTime() >= expirationDate.getTime()) {
                    return fail({
                        success: false,
                        data: this,
                        error: new SiwpError(
                            SiwpErrorType.EXPIRED_MESSAGE,
                            `${checkTime.toISOString()} < ${expirationDate.toISOString()}`,
                            `${checkTime.toISOString()} >= ${expirationDate.toISOString()}`
                        ),
                    });
                }
            }

            /** Message is valid already */
            if (this.notBefore) {
                const notBefore = new Date(this.notBefore);
                if (checkTime.getTime() < notBefore.getTime()) {
                    return fail({
                        success: false,
                        data: this,
                        error: new SiwpError(
                            SiwpErrorType.NOT_YET_VALID_MESSAGE,
                            `${checkTime.toISOString()} >= ${notBefore.toISOString()}`,
                            `${checkTime.toISOString()} < ${notBefore.toISOString()}`
                        ),
                    });
                }
            }

            console.log('Message is still valid. Proceeding with Address Verification.', this);

            // 2) Derive address from pubkey and compare
            const pubkeyCompressed = base64ToBytes(publicKey);     // 33 bytes
            const derived = bech32ify('pokt', ripemd160(sha256(pubkeyCompressed)));

            console.log('Derived address: ', derived, 'vs. Message address: ', this.address);

            if (derived !== this.address) {
                return fail({
                    success: false,
                    data: this,
                    error: new SiwpError(
                        SiwpErrorType.ADDRESS_MISMATCH,
                        this.address,
                        derived,
                    ),
                });
            }

            console.log('Creating ADR-36 sign-doc over MsgSignData');

            // 3) Recreate ADR-36 sign-doc over MsgSignData
            //    NOTE: ADR-36 mandates these exact fields: fee=[], gas="0", account/sequence="0", memo=""
            const signDoc: StdSignDoc = {
                chain_id: "",                       // ADR-36
                account_number: "0",                // ADR-36
                sequence: "0",                      // ADR-36
                fee: { amount: [], gas: "0" },      // ADR-36
                memo: "",                           // ADR-36
                msgs: [
                    {
                        type: "sign/MsgSignData",
                        value: {
                            signer: this.address,
                            data: Buffer.from(new TextEncoder().encode(this.prepareMessage())).toString("base64"),
                        },
                    } as any,
                ],
            };

            console.log('ADR-36 sign-doc: ', signDoc);

            console.log('Serializing ADR-36 sign-doc');
            const signBytes = serializeSignDoc(signDoc);     // Amino sign bytes

            console.log('ADR-36 sign-bytes: ', signBytes);

            console.log('Signing ADR-36 sign-bytes');

            const signHash = sha256(signBytes);         // 32-byte digest

            console.log('ADR-36 sign-hash: ', signHash);

            console.log('Getting signature bytes from base64');

            // 4) Verify secp256k1 signature (Keplr returns base64 compact 64-byte (r||s))
            const sig = base64ToBytes(signature);

            console.log('ADR-36 signature bytes: ', sig);

            if (sig.length !== 64) {
                return fail({
                    success: false,
                    data: this,
                    error: new SiwpError(
                        SiwpErrorType.INVALID_SIGNATURE,
                        `Signature must be 64 bytes compact (got ${sig.length}).`,
                    ),
                });
            }

            const ok = secp256k1.verify(sig, signHash, pubkeyCompressed);

            if (!ok) {
                return fail({
                    success: false,
                    data: this,
                    error: new SiwpError(
                        SiwpErrorType.INVALID_SIGNATURE,
                        `Signature does not match the message and public key.`,
                    ),
                });
            }

            return {
                success: true,
                data: this,
            };
        } catch (e: any) {
            return fail({
                success: false,
                data: this,
                error: new SiwpError(SiwpErrorType.SIGNATURE_VERIFICATION_ERROR, '', e.message),
            });
        }
    }
}
