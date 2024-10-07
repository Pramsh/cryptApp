// jest.setup.js
import Cipher from "./lib/Cipher";
// Attach CipherSingleton to the global object
global.Cipher = Cipher;
