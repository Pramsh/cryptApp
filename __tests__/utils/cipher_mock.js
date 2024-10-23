const testEncryptDecryptStr = "Let's encrypt and decrypt this string 323+'9.-!+è";
const testEncryptDecryptNumber = 12345;
const testEncryptDecryptBoolean = true;
const testEncryptDecryptObject = { key: "value" };
const testEncryptDecryptArray = [1, 2, 3, 4, 5];
const salt = "32ca2a023a14fefc29ae5522afc42ecc62f99e394c563977bc75cd1289aaeceb";
const encryptMockReqString = {
    body: {
        data: testEncryptDecryptStr,
        salt
    }
};
const encryptMockResString = {
    status: jest.fn(() => encryptMockResString),
    send: jest.fn()
};

const decryptMockReqString = {
    body: {
        salt
    }
};

const decryptMockResString = {
    status: jest.fn(() => decryptMockResString),
    send: jest.fn()
};

const encryptMockReqNumber = {
    body: {
        data: testEncryptDecryptNumber,
        salt
    }
};
const encryptMockResNumber = {
    status: jest.fn(() => encryptMockResNumber),
    send: jest.fn()
};


const encryptMockReqBoolean = {
    body: {
        data: testEncryptDecryptBoolean,
        salt
    }
};
const encryptMockResBoolean = {
    status: jest.fn(() => encryptMockResBoolean),
    send: jest.fn()
};

const encryptMockReqObject = {
    body: {
        data: testEncryptDecryptObject,
        salt
    }
};
const encryptMockResObject = {
    status: jest.fn(() => encryptMockResObject),
    send: jest.fn()
};

const decryptMockReqObject = {
    body: {
        salt
    }
};

const decryptMockResObject = {
    status: jest.fn(() => decryptMockResObject),
    send: jest.fn()
};

const encryptMockReqArray = {
    body: {
        data: testEncryptDecryptArray,
        salt
    }
};
const encryptMockResArray = {
    status: jest.fn(() => encryptMockResArray),
    send: jest.fn()
};

const decryptMockReqArray = {
    body: {
        salt
    }
};

const decryptMockResArray = {
    status: jest.fn(() => decryptMockResArray),
    send: jest.fn()
};

const rsa_genMockReq = {
    body: {
        userId: ""
    }
}

const rsa_genMockRes = {
    status: jest.fn(() => rsa_genMockRes),
    send: jest.fn()
}

export {
    testEncryptDecryptStr,
    testEncryptDecryptNumber,
    testEncryptDecryptBoolean,
    testEncryptDecryptObject,
    testEncryptDecryptArray,
    encryptMockReqString,
    encryptMockResString,
    decryptMockReqString,
    decryptMockResString,
    encryptMockReqNumber,
    encryptMockResNumber,
    encryptMockReqBoolean,
    encryptMockResBoolean,
    encryptMockReqObject,
    encryptMockResObject,
    decryptMockReqObject,
    decryptMockResObject,
    encryptMockReqArray,
    encryptMockResArray,
    decryptMockReqArray,
    decryptMockResArray,
    rsa_genMockReq,
    rsa_genMockRes
};