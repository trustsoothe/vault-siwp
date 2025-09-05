import {describe, test, expect, vitest} from 'vitest';
import { SiwpMessage } from './SiwpMessage';
import {SiwpError} from "./types";
import parsingNegativeObjects from '../../../test/parsing_negative_objects.json';
import parsingPositiveEntries from '../../../test/parsing_positive.json';
import verificationPositives from '../../../test/verification_positives.json';


describe('SiwpMessage', () => {
    describe('#validateMessages', () => {
        const parsingNegativeObjectsCases: [string, Record<string, any>][] = Object.entries(parsingNegativeObjects);
        test.each(parsingNegativeObjectsCases)('Fails when: %s', (_, testInputObject) => {
            try {
                new SiwpMessage(testInputObject);
            } catch (error) {
                expect(error).toBeInstanceOf(SiwpError);
            }
        });
    });

    describe('#prepareMessage', () => {
        const parsingPositiveEntriesCases: [string, { fields: Record<string, any>, message: string }][] = Object.entries(parsingPositiveEntries);
        test.each(parsingPositiveEntriesCases)('Generates message successfully: %s', (_, testInputObject) => {
            const siwpMessage = new SiwpMessage(testInputObject.fields);
            expect(siwpMessage.prepareMessage()).toBe(testInputObject.message);
        });
    });

    describe('#verifyERC4361', () => {
        const verificationPositiveCases: [string, Record<string, any>][] = Object.entries(verificationPositives);

        test.each(verificationPositiveCases)('Verifies message successfully: %s', async (_, testInputObject) => {
            vitest.useRealTimers();
            vitest.setSystemTime(new Date(testInputObject.time || testInputObject.issuedAt));

            const siwpMessage = new SiwpMessage(testInputObject);

            await expect(
                siwpMessage
                    .verifyERC4361({
                        signature: testInputObject.signature,
                        time: testInputObject.time || testInputObject.issuedAt,
                        publicKey: testInputObject.publicKey,
                    })
            ).resolves.toEqual({
                success: true,
                data: siwpMessage,
            });

            vitest.useRealTimers();
        });
    });
});
