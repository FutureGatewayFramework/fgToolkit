/*****************************************************************************
 * Copyright (c) 2019:
 * Istituto Nazionale di Fisica Nucleare (INFN), Italy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * @author <a href="mailto:riccardo.bruno@ct.infn.it">Riccardo Bruno</a>(INFN)
 *****************************************************************************/

/*
 * Perform a GET request to the given FG endpoint
 */
function doGet(url,
               access_token,
               successFunction,
               failureFunction) {
    doRequest("GET",
              url,
              access_token,
              null,
              successFunction,
              failureFunction);
}

/*
 * Perform a POST request to the given FG endpoint
 */
function doPost(url,
                access_token,
                req_data,
                successFunction,
                failureFunction) {
   doRequest("POST",
             url,
             access_token,
             req_data,
             successFunction,
             failureFunction);
}

/*
 * Perform a PATCH request to the given FG endpoint
 */
function doPatch(url,
                 access_token,
                 reqData,
                 successFunction,
                 failureFunction) {
   doRequest("PATCH",
             url,
             access_token,
             req_data,
             successFunction,
             failureFunction);
}

/*
 * Perform a DELETE request to the given FG endpoint
 */
function doDelete(url,
                  access_token,
                  successFunction,
                  failureFunction) {
   doRequest("DELETE",
             url,
             access_token,
             null,
             successFunction,
             failureFunction);
}

/*
 * Generi call to perform an HTTP request to a given FG endpoint with
 * eventually given data.
 */
function doRequest(method,
                   url,
                   access_token,
                   req_data,
                   successFunction,
                   failureFunction) {
    if(req_data != null) {
        str_data = JSON.stringify(req_data);
    } else {
        str_data = null;
    }
    $.ajax({
        type: "GET",
        url: url,
        dataType: "json",
        headers: {
            'Authorization': access_token,
        },
        contentType: 'application/json',
        crossDomain: true,
        data: str_data,
        success: successFunction,
        error: failureFunction
   });
}
