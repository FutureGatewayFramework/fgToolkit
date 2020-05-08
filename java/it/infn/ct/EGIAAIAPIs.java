/**************************************************************************
 * Copyright (c) 2011:
 * Istituto Nazionale di Fisica Nucleare (INFN), Italy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *     @author <a href="mailto:riccardo.bruno@ct.infn.it">Riccardo Bruno</a>(INFN)
 *     ****************************************************************************/
package it.infn.ct;

import java.io.*;
import java.net.*;
import java.util.Base64;
import com.liferay.portal.kernel.json.*;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;

public class EGIAAIAPIs {

	private final String APIURL = "https://aai.egi.eu/api/v1";
	private final String APILogin = "ltos-admin";
	private final String APIPassword = "sAF@wux6tuN3U&qw";
	private final String USER_AGENT = "Mozilla/5.0";

	private static Log _log = LogFactoryUtil.getLog(FutureGatewayAPIs.class);
	private static String LS = System.getProperty("line.separator");

        private boolean errFlag=false;
        private String errMessage="";

        private void setError(String apiEndpoint, String errMessage) {
            errFlag = true;
            errMessage = "Failed EGI API call: '" + apiEndpoint + "'" + LS +
                         "Error: '" + errMessage + "'";
            _log.error(errMessage);
        }

	private String encodeCredentials() {
		String cred = APILogin + ":" + APIPassword;
		return Base64.getEncoder().encodeToString(cred.getBytes());
	}

	public boolean verifySub(String sub) {
            errFlag = false;
            JSONObject apiData = doGet(APIURL + "/VoMembers/" + sub);
            return apiData.getString("status").equals("Active");
	}

	private JSONObject doGet(String url) {
            JSONObject jsonObj = null;
            try {
                URL obj = new URL(url);
                HttpURLConnection conn = (HttpURLConnection) obj.openConnection();
                conn.setConnectTimeout(15000);
                conn.setRequestMethod("GET");	
                conn.setDoOutput(true);
                conn.setRequestProperty("Authorization", "Basic " + encodeCredentials());
                conn.setRequestProperty("Content-Type", "application/json;charset=utf-8");
                int responseCode = conn.getResponseCode();
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuffer response = new StringBuffer();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();
		String jsonResponse = response.substring(1, response.length()-1);
		jsonObj = JSONFactoryUtil.createJSONObject(jsonResponse);
            } catch(MalformedURLException e) {
                setError(url, e.toString());
            } catch(IOException e) {
                setError(url, e.toString());
            } catch(JSONException e) {
                setError(url, e.toString());
            }
            _log.debug("json: '" + jsonObj + "'"); 
            return jsonObj;
	}

}
