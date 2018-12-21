import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;

import com.lj.extapi.common.PemImport;
import com.lj.extapi.vo.SamsungPassRsVO;

public class samsungpass {
	@Value("#{localProperty['samsungPass.key.path']}")
	private String samsungPassKeyPath;

	@Value("#{localProperty['samsungPass.cert.path']}")
	private String samsungPassCertPath;

	@Value("#{localProperty['samsungPass.keystore.password']}")
	private String samsungPassPassWord;

	@Value("#{localProperty['samsungPass.server.url']}")
	private String samsungPassUrl;

	@Value("#{localProperty['samsungPass.header.appId']}")
	private String samsungPassAppId;

	@Value("#{localProperty['samsungPass.header.appCertHash']}")
	private String samsungPassAppHash;

	@Value("#{localProperty['samsungPass.body.needUserIdYn']}")
	private String samsungpassNeedUserId;

	@Autowired
	private Environment env;

	@Override
	public SamsungPassRsVO getSamsungpass(String authToken, HttpServletRequest request) throws Exception {
		SamsungPassRsVO result = new SamsungPassRsVO();
		String reqId = UUID.randomUUID().toString();
		long strConnectionTime = System.currentTimeMillis();
		BufferedReader in = null;
		
		try {
			File key = new File(samsungPassKeyPath);
			File cert = new File(samsungPassCertPath);

			// URL 호출
			String url = samsungPassUrl + "?reqId=" + reqId + "&authToken=" + authToken + "&needUserIdYn="
					+ samsungpassNeedUserId;

			URL obj = new URL(url);
			HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

			// optional default is GET
			con.setRequestMethod("GET");
			con.setRequestProperty("User-Agent", "Chrome/version");
			con.setRequestProperty("Accept-Charset", "UTF-8");
			con.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
			con.setRequestProperty("x-spass-appId", samsungPassAppId);
			con.setRequestProperty("x-spass-appCertHash", samsungPassAppHash);
			con.setSSLSocketFactory(PemImport.createSSLFactory(key, cert, samsungPassPassWord));

			// AWS 504 ERROR
			con.setConnectTimeout(10000);
			con.setReadTimeout(10000);
			con.setDoInput(true);

			if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
				in = new BufferedReader(new InputStreamReader(con.getInputStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();

				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();
				JSONObject responseJson = new JSONObject(response.toString());
				result.setResultCode(responseJson.getString("resultCode"));
				result.setResultMessage(responseJson.getString("resultMessage"));
				result.setResponseBody(response.toString());
			} else {
				in = new BufferedReader(new InputStreamReader(con.getErrorStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();

				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				in.close();
				JSONObject responseJson = new JSONObject(response.toString());
				result.setReqId(reqId);
				result.setResultCode(responseJson.getString("resultCode"));
				result.setResultMessage(responseJson.getString("resultMessage"));
				result.setResponseBody(response.toString());
			}
		} catch (FileNotFoundException e) {
			LOGGER.error("FileNotFound : ", e);
			result.setReqId(reqId);
			result.setResultMessage("FAIL");
			result.setResponseBody(e.getMessage());
		} catch (ConnectException e) {
			LOGGER.error("Connection Fail: ", e);
			long endConnectionTime = System.currentTimeMillis();
			String time = convertMiliseconds(strConnectionTime - endConnectionTime);
			result.setReqId(reqId);
			result.setResultMessage("FAIL");
			result.setResponseBody("time : " + time + "\n" + e.getMessage());
		} catch (Exception e) {
			LOGGER.error("Exception : ", e);
			result.setReqId(reqId);
			result.setResultMessage("FAIL");
			result.setResponseBody(e.getMessage());
		} finally {
		    if (in != null) {
		        safeClose(in);
		      }
		}
		return result;
	}
}
