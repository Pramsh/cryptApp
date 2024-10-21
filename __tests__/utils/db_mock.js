const get_mock = {
    status: jest.fn(() => get_mock),
    send: jest.fn()
}

const jwtMockRes = {
    status: jest.fn(() => jwtMockRes),
    send: jest.fn()
};

const signMockRes = {
    status: jest.fn(() => signMockRes),
    send: jest.fn()
};