// Во многих фреймфорках или библиотеках - методы для работы с OAuth2 уже готовые и не нужно будет их писать вручную
// В этом проекте мы все делаем вручную, чтобы вы лучше поняли весь алгоритм действий

// константы для использования во всем файле js
const CLIENT_ID = "todoapp-client"; // название должен совпадать c клиентом из KeyCloak
const SCOPE = "openid"; // какие данные хотите получить помимо access token (refresh token, id token) - можно через пробел указывать неск значений
const GRANT_TYPE_AUTH_CODE = "authorization_code"; // для получения access token мы отправляем auth code
const RESPONSE_TYPE_CODE = "code"; // для получения authorization code

// ALG - используются как параметры в разных методах шифрования, где-то с тире, где-то без тире
const SHA_256 = "SHA-256";
const S256 = "S256";

var accessToken = "";

// !! в каждой версии KeyCloak могут меняться URI - поэтому нужно сверяться с документацией
const KEYCLOAK_URI = "https://localhost:8443/realms/todoapp-realm/protocol/openid-connect"; // общий URI KeyCloak
const AUTH_CODE_REDIRECT_URI = "https://localhost:8080/redirect"; // куда auth server будет отправлять auth code
const ACCESS_TOKEN_REDIRECT_URI = "https://localhost:8080/redirect"; // куда auth server будет отправлять access token и другие токены
const RESOURCE_SERVER_URI = "https://localhost:8901"; // где находится API Resource Server



// запускаем цикл действий для grant type = PKCE (Proof Key for Code Exchange), который хорошо подходит для JS приложений в браузере
// https://www.rfc-editor.org/rfc/rfc7636
function initValues() {

    // нужен только для первого запроса (авторизация), чтобы клиент убедился, что ответ от AuthServer (после авторизации) пришел именно на его нужный запрос
    // защита от CSRF атак
    var state = generateState(30);
    document.getElementById("originalState").innerHTML = state;
    console.log("state = " + state)


    var codeVerifier = generateCodeVerifier();
    document.getElementById("codeVerifier").innerHTML = codeVerifier;
    console.log("codeVerifier = " + codeVerifier);

    // реактивный код - реакция не выполнения асинхронной функции
    // асинхронный вызов - т.к. функция хеширования возвращает объект Promise, на который нужно подписываться (принцип реактивного кода)
    generateCodeChallenge(codeVerifier).then(codeChallenge => {
        // console.log("codeChallenge = " + codeChallenge);
        requestAuthCode(state, codeChallenge) // запрашиваем auth code, т.к. все параметры сформировали и можем отправлять запрос
    });

}

// https://www.rfc-editor.org/rfc/rfc7636.html#page-8
// в реальных проектах эти функции скорее всего уже реализованы в библиотеке и вы просто вызывает эту функцию
function generateCodeVerifier() {
    var randomByteArray = new Uint8Array(43);
    window.crypto.getRandomValues(randomByteArray);
    return base64urlencode(randomByteArray); // формат Base64 на основе массива байтов

    // про Uint8Array https://learn.javascript.ru/arraybuffer-binary-arrays

}


// преобразование массива байтов в формат текстовый формат Base64
// https://ru.wikipedia.org/wiki/Base64
function base64urlencode(sourceValue) {
    var stringValue = String.fromCharCode.apply(null, sourceValue);
    var base64Encoded = btoa(stringValue);
    var base64urlEncoded = base64Encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return base64urlEncoded;
}


// зачем нужен state - чтобы на втором шаге будем сравнивать его со значением от AuthServer
// тем самым убедимся, что ответ пришел именно на наш запрос
function generateState(length) {

    // генерим случайные символы из англ алфавита
    var state = "";
    var alphaNumericCharacters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var alphaNumericCharactersLength = alphaNumericCharacters.length;
    for (var i = 0; i < length; i++) {
        state += alphaNumericCharacters.charAt(Math.floor(Math.random() * alphaNumericCharactersLength));
    }

    return state;
}


// https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
// В реальных проектах эти функции скорее всего уже реализованы в библиотеке и вы просто вызывает эту функцию
async function generateCodeChallenge(codeVerifier) {

    var textEncoder = new TextEncoder('US-ASCII');
    var encodedValue = textEncoder.encode(codeVerifier); // кодируем в массив байтов ранее полученный code_verifier
    var digest = await window.crypto.subtle.digest(SHA_256, encodedValue);
    // поддержка в браузерах функции шифрования https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle

    return base64urlencode(Array.from(new Uint8Array(digest)));  // Base64 формат на основе хеш-функции, которая применятся на codeVerifier

}


// запрос в auth server на получение auth code (который потом будем менять на access token и другие токены)
function requestAuthCode(state, codeChallenge) {

    // в каждой версии KeyCloak может изменяться URL - поэтому нужно сверяться с документацией
    var authUrl = KEYCLOAK_URI + "/auth";

    authUrl += "?response_type=" + RESPONSE_TYPE_CODE; // указываем auth server, что хотим получить auth code
    authUrl += "&client_id=" + CLIENT_ID; // берем из auth server
    authUrl += "&state=" + state; // auth server сохранит это значение себе и отправит в след. запросе (вместе с access token) и клиент сможет убедиться, что ответ пришел именно на его запрос
    authUrl += "&scope=" + SCOPE; // какие данные хотите получить от auth server, помимо access token
    authUrl += "&code_challenge=" + codeChallenge; // чтобы auth server убедился - запрос пришел именно то того пользователя, кто авторизовался ранее и получил auth code
    authUrl += "&code_challenge_method=" + S256; // функция применяется к code_verifier, которые auth server получил в прошлом запросе - затем он сравнит результат с переданным code_challenge
    authUrl += "&redirect_uri=" + AUTH_CODE_REDIRECT_URI; // куда auth server будет отправлять ответ

    // открываем окно для авторизации
    // если сделаете размер меньше, будет мобильная версия (KeyCloak автоматически изменит стиль окна)
    window.open(authUrl, 'auth window', 'width=800,height=600,left=350,top=200');
}


// получаем все токены из auth server (access token, refresh token, id token - зависит от настроек scope)
function requestTokens(stateFromAuthServer, authCode) { // idea может показывать, что функция нидге не используется, но это не так, просто он не может определить вызов из другого window

    var originalState = document.getElementById("originalState").innerHTML;
    // console.log(authCode);

    // убеждаемся, что это ответ именно на наш запрос, который отправляли ранее (для авторизации на auth server)
    if (stateFromAuthServer === originalState) {

        // передаем в auth server, чтобы он убедился, что мы - тот же клиент, который ранее делал запрос на получение auth code
        var codeVerifier = document.getElementById("codeVerifier").innerHTML;

        // набор параметров для правильного обращения к auth server
        var data = {
            "grant_type": GRANT_TYPE_AUTH_CODE, // уведомляес auth server, что у нас есть auth code и с помощью него хотим получить access token
            "client_id": CLIENT_ID, // берем из KeyCloak
            "code": authCode, // полученное ранее значение (после авторизации в auth server)
            "code_verifier": codeVerifier,// передаем в auth server, чтобы он убедился, что мы - тот же клиент, который ранее делал запрос на получение auth code
            "redirect_uri": ACCESS_TOKEN_REDIRECT_URI // куда auth server будет отправлять ответ
        };

        $.ajax({ // ajax запрос для параллельного вызова
            beforeSend: function (request) { // обязательные заголовки
                request.setRequestHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
            },
            type: "POST", // тип запроса обязательно должен быть POST
            url: KEYCLOAK_URI + "/token", // адрес обращения
            data: data, // параметры запроса
            success: accessTokenResponse, // (callback) какой метод вызывать после выполнения запроса (туда будет передан результат)
            dataType: "json" // в каком формате получем ответ от auth server
        });
    } else {
        alert("Error state value");
    }
}


// получить access token
function accessTokenResponse(data, status, jqXHR) { // // эти параметры передаются автоматически, data будет в формате JSON

     accessToken = data["access_token"];
    console.log("access_token = " + accessToken);
    // получить данные из Resource Server, добавив в запрос access token
   // getDataFromResourceServer(accessToken);
}


// получить данные из Resource Server, добавив в запрос access token
function getDataFromResourceServer() {

    // ajax запрос (параллельный вызов)
    $.ajax({
        beforeSend: function (request) { // обязательные заголовки
            request.setRequestHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
            request.setRequestHeader("Authorization", "Bearer " + accessToken); // задачем Bearer c access token
        },
        type: "GET", // тип запроса (обязательно должен быть get)
        url: RESOURCE_SERVER_URI+"/user/data", // адрес, куда отправляем запрос
        success: resourceServerResponse, // метод для выполнения, если запрос сработает успешно (callback)
        dataType: "text" // в каком формате ожидаем ответ от auth server (в нашем случае это обычный текст - для упрощения, но чаще всего это JSON)
    });
}

// обработка ответа от resource server (callback)
function resourceServerResponse(data, status, jqXHR) { // эти параметры передаются автоматически

    // данные можем отображать на странице - все зависит уже от frontend приложения
    document.getElementById("userdata").innerHTML = data;
    console.log("resource server data = " + data);
}