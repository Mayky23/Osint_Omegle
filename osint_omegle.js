// Configuración de URLs para cada API gratuita
const ipApiUrl = "http://ip-api.com/json/";
const ipWhoisUrl = "https://free.ipwhois.io/json/";
const abuseIpDbUrl = "https://api.abuseipdb.com/api/v2/check";
const hackerTargetUrl = "https://api.hackertarget.com/aslookup/?q=";

// Headers para AbuseIPDB (requiere una clave gratuita)
const abuseIpDbApiKey = "YOUR_ABUSEIPDB_API_KEY";

// Función para obtener datos básicos de IP-API
async function getIpApiData(ip) {
  const url = `${ipApiUrl}${ip}`;
  try {
    const response = await fetch(url);
    const data = await response.json();

    const output = `
      ---------------------
      IP: ${data.query}
      País: ${data.country}
      Región: ${data.regionName}
      Ciudad: ${data.city}
      Código Postal: ${data.zip}
      Latitud: ${data.lat}
      Longitud: ${data.lon}
      ISP: ${data.isp}
      Organización: ${data.org}
      ---------------------
    `;
    console.log(output);
  } catch (error) {
    console.error("Error obteniendo datos de IP-API:", error);
  }
}

// Función para obtener datos adicionales de IPWhois
async function getIpWhoisData(ip) {
  const url = `${ipWhoisUrl}${ip}`;
  try {
    const response = await fetch(url);
    const data = await response.json();

    const output = `
      ---------------------
      IP: ${data.ip}
      Continente: ${data.continent}
      País: ${data.country}
      Región: ${data.region}
      Ciudad: ${data.city}
      Proveedor de Internet: ${data.org}
      ASN: ${data.asn}
      ---------------------
    `;
    console.log(output);
  } catch (error) {
    console.error("Error obteniendo datos de IPWhois:", error);
  }
}

// Función para consultar historial de abuso con AbuseIPDB
async function getAbuseIpData(ip) {
  const url = `${abuseIpDbUrl}?ipAddress=${ip}`;
  try {
    const response = await fetch(url, {
      headers: {
        "Key": abuseIpDbApiKey,
        "Accept": "application/json"
      }
    });
    const data = await response.json();

    const output = `
      ---------------------
      IP: ${data.data.ipAddress}
      Histórico de abuso: ${data.data.abuseConfidenceScore}%
      Últimos reportes: ${data.data.totalReports}
      Última actividad: ${data.data.lastReportedAt || "N/A"}
      ---------------------
    `;
    console.log(output);
  } catch (error) {
    console.error("Error obteniendo datos de AbuseIPDB:", error);
  }
}

// Función para consultar ASN y datos de red con HackerTarget
async function getAsnData(ip) {
  const url = `${hackerTargetUrl}${ip}`;
  try {
    const response = await fetch(url);
    const data = await response.text();

    const output = `
      ---------------------
      ASN y datos de red:
      ${data}
      ---------------------
    `;
    console.log(output);
  } catch (error) {
    console.error("Error obteniendo datos de ASN con HackerTarget:", error);
  }
}

// Función principal para coordinar todas las consultas
async function getLocation(ip) {
  console.log(`Obteniendo datos de IP: ${ip}`);
  
  // Llamar a cada función de OSINT para obtener datos
  await getIpApiData(ip);        // Datos básicos de IP y geolocalización
  await getIpWhoisData(ip);      // Datos de WHOIS de IPWhois
  await getAbuseIpData(ip);      // Historial de abuso en AbuseIPDB
  await getAsnData(ip);          // Datos de ASN en HackerTarget
}

// Interceptar ICE Candidates en WebRTC y extraer IPs
window.oRTCPeerConnection = window.oRTCPeerConnection || window.RTCPeerConnection;
window.RTCPeerConnection = function (...args) {
  const pc = new window.oRTCPeerConnection(...args);

  pc.oaddIceCandidate = pc.addIceCandidate;
  pc.addIceCandidate = function (iceCandidate, ...rest) {
    const fields = iceCandidate.candidate.split(" ");
    const ip = fields[4];

    if (fields[7] === "srflx") {
      getLocation(ip); // Llamada para obtener todos los datos posibles de la IP
    }

    return pc.oaddIceCandidate(iceCandidate, ...rest);
  };

  return pc;
};
