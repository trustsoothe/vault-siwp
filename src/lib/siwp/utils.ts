import { ripemd160 } from '@noble/hashes/ripemd160'
import { toBech32 } from '@cosmjs/encoding'

const ISO8601 =
    /^(?<date>[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]))[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$/;
;


function generateRandomBitString(bitLength: number): { binary: string, hex: string } {
    let binaryString = '';
    let hexString = '';

    for (let i = 0; i < bitLength; i++) {
        const randomBit = Math.random() < 0.5 ? '0' : '1';
        binaryString += randomBit;
    }

    for (let i = 0; i < bitLength; i += 4) {
        const nibble = binaryString.slice(i, i + 4);
        const hexDigit = parseInt(nibble, 2).toString(16);
        hexString += hexDigit;
    }

    return { binary: binaryString, hex: hexString };
}

/**
 * This method leverages a native CSPRNG with support for both browser and Node.js
 * environments in order generate a cryptographically secure nonce for use in the
 * SiwpMessage in order to prevent replay attacks.
 *
 * 96 bits has been chosen as a number to sufficiently balance size and security considerations
 * relative to the lifespan of its usage.
 *
 * @returns cryptographically generated random nonce with 96 bits of entropy encoded with
 * an alphanumeric character set.
 */
export const generateNonce = (): string => {
    const nonce = generateRandomBitString(96).hex;
    if (!nonce || nonce.length < 8) {
        throw new Error('Error during nonce creation.');
    }
    return nonce;
};

/**
 * This method matches the given date string against the ISO-8601 regex and also
 * performs checks if it's a valid date.
 * @param inputDate any string to be validated against ISO-8601
 * @returns boolean indicating if the provided date is valid and conformant to ISO-8601
 */
export const isValidISO8601Date = (inputDate: string): boolean => {
    /* Split groups and make sure inputDate is in ISO8601 format */
    const inputMatch = ISO8601.exec(inputDate);

    /* if inputMatch is null the date is not ISO-8601 */
    if (!inputMatch || !inputMatch.groups || !inputMatch.groups.date) {
        return false;
    }

    /* Creates a date object with input date to parse for invalid days e.g. Feb, 30 -> Mar, 01 */
    const inputDateParsed = new Date(inputMatch.groups.date).toISOString();

    /* Get groups from new parsed date to compare with the original input */
    const parsedInputMatch = ISO8601.exec(inputDateParsed);

    if (!parsedInputMatch || !parsedInputMatch.groups || !parsedInputMatch.groups.date) {
        return false;
    }

    /* Compare remaining fields */
    return inputMatch.groups.date === parsedInputMatch.groups.date;
};

function hexStringToByteArray(str: string): Uint8Array {
    const hexRegExp = str.match(/.{1,2}/g);

    if (hexRegExp) {
        return Uint8Array.from(hexRegExp.map((byte) => parseInt(byte, 16)));
    }

    throw new Error("Invalid hex string");
}

export const getAddressFromPublicKey = async (publicKey: string): Promise<string> => {
    const bytes = Uint8Array.from(Buffer.from(publicKey, 'hex'));
    const sha256 = await globalThis.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
        bytes,
    );
    // @ts-ignore
    const addressBytes = ripemd160(sha256);

    return toBech32("pokt", addressBytes);
}
