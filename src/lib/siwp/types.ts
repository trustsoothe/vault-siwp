import {SiwpMessage} from "./SiwpMessage";

export interface VerifyERC4361Params {
    /** Signature of the message signed by the wallet */
    signature: string;

    /** The signer's public as it is not recoverable from the message and signature in Ed25519 */
    publicKey: string;

    /** RFC 3986 URI scheme for the authority that is requesting the signing. */
    scheme?: string;

    /** RFC 4501 dns authority that is requesting the signing. */
    domain?: string;

    /** Randomized token used to prevent replay attacks, at least 8 alphanumeric characters. */
    nonce?: string;

    /**ISO 8601 datetime string of the current time. */
    time?: string;
}

export interface VerifyAdr36Params {
    /** Base64 signature returned by the wallet (Keplr signArbitrary result.signature) */
    signatureB64: string;

    /** Wallet public key base64 (Keplr signArbitrary result.pub_key.value). 33-byte secp256k1 compressed. */
    pubKeyB64: string;

    /** Bech32 HRP (prefix) to derive & compare the address (default: "pokt") */
    hrp?: string;

    /** RFC 3986 URI scheme for the authority that is requesting the signing. */
    scheme?: string;

    /** RFC 4501 dns authority that is requesting the signing. */
    domain?: string;
}

export interface VerifyAdr36SiwpResult {
    success: boolean;
    reason?: string;
    derivedAddress?: string;
}


export interface VerifyOpts {
    /** If the library should reject promises on errors, defaults to false */
    suppressExceptions?: boolean;
}

/**
 * Returned on verifications.
 */
export interface SiwpResponse {
    /** Boolean representing if the message was verified with success. */
    success: boolean;

    /** If present `success` MUST be false and will provide extra information on the failure reason. */
    error?: SiwpError;

    /** Original message that was verified. */
    data: SiwpMessage;
}

/**
 * Interface used to return errors in SiweResponses.
 */
export class SiwpError {
    constructor(type: SiwpErrorType | string, expected?: string, received?: string) {
        this.type = type;
        this.expected = expected;
        this.received = received;
    }

    /** Type of the error. */
    type: SiwpErrorType | string;

    /** Expected value or condition to pass. */
    expected?: string;

    /** Received value that caused the failure. */
    received?: string;
}

/**
 * Possible message error types.
 */
export enum SiwpErrorType {
    /** `expirationTime` is present and in the past. */
    EXPIRED_MESSAGE = 'Expired message.',

    /** `domain` is not a valid authority or is empty. */
    INVALID_DOMAIN = 'Invalid domain.',

    /** `scheme` don't match the scheme provided for verification. */
    SCHEME_MISMATCH = 'Scheme does not match provided scheme for verification.',

    /** `domain` don't match the domain provided for verification. */
    DOMAIN_MISMATCH = 'Domain does not match provided domain for verification.',

    /** `nonce` don't match the nonce provided for verification. */
    NONCE_MISMATCH = 'Nonce does not match provided nonce for verification.',

    /** `address` is not valid */
    INVALID_ADDRESS = 'Invalid address.',

    /** `uri` does not conform to RFC 3986. */
    INVALID_URI = 'URI does not conform to RFC 3986.',

    /** `nonce` is smaller than 8 characters or is not alphanumeric */
    INVALID_NONCE = 'Nonce size smaller then 8 characters or is not alphanumeric.',

    /** `notBefore` is present and in the future. */
    NOT_YET_VALID_MESSAGE = 'Message is not valid yet.',

    /** Signature doesn't match the address of the message. */
    INVALID_SIGNATURE = 'Signature does not match the message and public key.',

    /** Signature verification failed */
    SIGNATURE_VERIFICATION_ERROR = 'Error during signature verification. Please check the signature.',

    /** The address recovered from the public key does not match the one in the message */
    ADDRESS_MISMATCH = 'Address does not match the public key.',

    /** `address` is not recoverable from the public key. */
    ADDRESS_UNRECOVERABLE = 'Address is not recoverable from the public key.',

    /** `expirationTime`, `notBefore` or `issuedAt` not complient to ISO-8601. */
    INVALID_TIME_FORMAT = 'Invalid time format.',

    /** `version` is not 1. */
    INVALID_MESSAGE_VERSION = 'Invalid message version.',

    /** Thrown when some required field is missing. */
    UNABLE_TO_PARSE = 'Unable to parse the message.',

    /** `chainId` is neither mainnet or testnet */
    INVALID_CHAIN_ID = 'Expired message.',
}
