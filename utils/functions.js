import { JWTexpirationTimeValue, IPheader } from "./constants.js";
export const isValidJSON = (str) => {
    if (typeof str !== 'string') return false;
    str = str.trim();
    if (str === '') return false;
    try {
        JSON.parse(str);
    } catch (e) {
        return false; // If parsing fails, return false
    }
    return true; // If parsing succeeds, return true
}

//Function to handle error and status
//msg is  optional
export const statusAndError = (err, msg) => ({
    message: msg ? msg : err?.message ?? "Internal Server Error",
    status: err?.status ?? 500
})
     

export const JWTexpirationTime = () => Math.floor(Date.now() / 1000) + (JWTexpirationTimeValue) //1h

export const cLog = (msg,severity = "log") => {console[severity](msg)}


export const divideChunks = (arr, maxLength) => {
    const chunks = [];
    let i = 0;
    const total = arr.length;
    while (i < total) {
      chunks.push(arr.splice(0, maxLength));
      i += maxLength;
    }
    return chunks;
  };

  export const getClientIP = (req) => 
    req.headers[IPheader].length ?
        req.headers[IPheader].split(',')[0] :
        req.connection.remoteAddress
  