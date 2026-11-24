const DEVICE_KEY = "device_uuid";

// Is browser ka permanent device ID.
// Pehli baar random UUID banta hai aur localStorage mein rehta hai, phir hamesha wahi milta hai.
export function getDeviceUuid() {
    let id = localStorage.getItem(DEVICE_KEY);

    if (!id) {
        id = crypto.randomUUID();
        localStorage.setItem(DEVICE_KEY, id);
        console.log("[device] new device id created:", id);
    }

    return id;
}

// Device ki jaankari, jo login ke saath server ko jaati hai
export function getDeviceInfo() {
    return {
        device_name: navigator.platform || "browser",
        device_type: "web",
        os_name: navigator.userAgentData?.platform ?? navigator.platform ?? "",
        os_version: "",
        app_version: "1.0.0",
        screen_resolution: `${screen.width}x${screen.height}`
    };
}

// Login ke baad har protected API call mein ye headers bhejne hain:
// token + device ID, dono mil ke session ko is device se bandhte hain
export function authHeaders(accessToken) {
    return {
        Authorization: `Bearer ${accessToken}`,
        "X-Device-Id": getDeviceUuid()
    };
}
