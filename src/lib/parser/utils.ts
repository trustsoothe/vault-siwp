export const isValidPocketAddress = (address: string): boolean => {
    return /^pokt[ac-hj-np-z0-9]{39}$/.test(address);
}
