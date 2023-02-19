// Во многих фреймфорках или библиотеках - методы для работы с OAuth2 уже готовые и не нужно будет их писать вручную
// В этом проекте мы все делаем вручную, чтобы вы лучше поняли весь алгоритм действий

// константы для использования во всем файле js
const CLIENT_ID = "todoapp-client"; // название должен совпадать c клиентом из KeyCloak
const SCOPE = "openid"; // какие данные хотите получить помимо access token (refresh token, id token, email и пр.) - можно через пробел указывать неск значений
const GRANT_TYPE_AUTH_CODE = "authorization_code"; // для получения access token мы отправляем auth code
const GRANT_TYPE_REFRESH_TOKEN = "refresh_token"; // для обмена refresh token на новый access token
const RESPONSE_TYPE_CODE = "code"; // для получения authorization code

// ALG - используются как параметры в разных методах шифрования, где-то с тире, где-то без тире
const SHA_256 = "SHA-256"
const S256 = "S256";

// !! в каждой версии KeyCloak могут меняться URI - поэтому нужно сверяться с документацией
const KEYCLOAK_URI = "https://localhost:8443/realms/todoapp-realm/protocol/openid-connect"; // общий URI KeyCloak
const CLIENT_ROOT_URL = "https://localhost:8080"; // куда auth server будет отправлять auth code
const RESOURCE_SERVER_URL = "https://localhost:8901"; // где находится API Resource Server

// сохранение значений в память
var accessToken = ""; // значение сбросится, если обновить веб страницу
var refreshToken = ""; // для получения нового access token без повторной авторизации в окне
var idToken = ""; // данные пользователя

// ключи для сохранения в localStorage
const ID_TOKEN_KEY = "IT";
const REFRESH_TOKEN_KEY = "RT";
const STATE_KEY = "ST";
const CODE_VERIFIER_KEY = "CV";



// вызывается при обновлении страницы
function initPage() {

    refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);

    // если есть сохраненный ранее Refresh Token, то меняем его на Access Token
    if (refreshToken) {
        exchangeRefreshToAccessToken();
    } else { // иначе запускаем полный цикл PKCE с вводом логин-пароль

        if (!checkAuthCode()) { // если текущий запрос - это не ответ от auth server с новым code (через redirect uri)
            initAccessToken();  // значит уже авторизовались и просто получаем новые токены

            // данные с сервера можем получать автоматически, как только получили новые токены!
        }

    }


}



// запускаем цикл действий для grant type = PKCE (Proof Key for Code Exchange), который хорошо подходит для JS приложений в браузере
// https://www.rfc-editor.org/rfc/rfc7636
function initAccessToken() {
    // нужен только для первого запроса (авторизация), чтобы клиент убедился, что ответ от AuthServer (после авторизации) пришел именно на его нужный запрос
    // защита от CSRF атак
    var state = generateState(30);
    // document.getElementById("originalState").innerHTML = state;
    // console.log("state = " + state)
    localStorage.setItem(STATE_KEY, state);


    var codeVerifier = generateCodeVerifier();
    // document.getElementById("codeVerifier").innerHTML = codeVerifier;
    localStorage.setItem(CODE_VERIFIER_KEY, codeVerifier);

    // console.log("codeVerifier = " + codeVerifier);

    // реактивный код - реакция не выполнения асинхронной функции
    // асинхронный вызов - т.к. функция хеширования возвращает объект Promise, на который нужно подписываться (принцип реактивного кода)
    generateCodeChallenge(codeVerifier).then(codeChallenge => {
        // console.log("codeChallenge = " + codeChallenge);
        requestAuthCode(state, codeChallenge) // запрашиваем auth code, т.к. все параметры сформировали и можем отправлять запрос
    });

}



// проверяем, если в текущем запросе есть параметры ответа от auth server - значит это ответ с новым auth code
function checkAuthCode() {
    var urlParams = new URLSearchParams(window.location.search);
    var authCode = urlParams.get('code'),
        state = urlParams.get('state'),
        error = urlParams.get('error'),
        errorDescription = urlParams.get('error_description');

    // если вдруг code не пришел в ответе
    if (!authCode) {
        return false;
    }

    requestTokens(state, authCode) // получаем новые токены

    return true;
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
    authUrl += "&redirect_uri=" + CLIENT_ROOT_URL; // куда auth server будет отправлять ответ

    window.open(authUrl, '_self'); // открываем в этом же окне (self) окно авторизации KeyCloak
}


// получаем все токены из auth server (access token, refresh token, id token - зависит от настроек scope)
function requestTokens(stateFromAuthServer, authCode) { // idea может показывать, что функция нидге не используется, но это не так, просто он не может определить вызов из другого window

    // var originalState = document.getElementById("originalState").innerHTML;
    // console.log(authCode);
    var originalState = localStorage.getItem(STATE_KEY);

    // убеждаемся, что это ответ именно на наш запрос, который отправляли ранее (для авторизации на auth server)
    if (stateFromAuthServer === originalState) {

        // передаем в auth server, чтобы он убедился, что мы - тот же клиент, который ранее делал запрос на получение auth code
        var codeVerifier = localStorage.getItem(CODE_VERIFIER_KEY);

        // набор параметров для правильного обращения к auth server
        var data = {
            "grant_type": GRANT_TYPE_AUTH_CODE, // уведомляем auth server, что у нас есть auth code и с помощью него хотим получить access token
            "client_id": CLIENT_ID, // берем из KeyCloak
            "code": authCode, // полученное ранее значение (после авторизации в auth server)
            "code_verifier": codeVerifier,// передаем в auth server, чтобы он убедился, что мы - тот же клиент, который ранее делал запрос на получение auth code
            "redirect_uri": CLIENT_ROOT_URL // куда auth server будет отправлять ответ
        };

        $.ajax({ // ajax запрос для параллельного вызова
            beforeSend: function (request) { // обязательные заголовки
                request.setRequestHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
            },
            type: "POST", // тип запроса обязательно должен быть POST
            url: KEYCLOAK_URI + "/token", // адрес обращения
            data: data, // параметры запроса
            success: accessTokenResponse, // (callback) какой метод вызывать после выполнения запроса (туда будет передан результат)
            dataType: "json" // в каком формате получаем ответ от auth server
        });
    } else {
        initAccessToken(); // если ошибка - заново отправляем для ввода логин-пароль
    }
}


// получить access token
function accessTokenResponse(data, status, jqXHR) { // // эти параметры передаются автоматически, data будет в формате JSON

    // очищаем временно сохраненные значения
    localStorage.removeItem(STATE_KEY);
    localStorage.removeItem(CODE_VERIFIER_KEY);

    // сохраняем в глоб. переменную (сбросится только после перезагрузки страницы)
    accessToken = data["access_token"];
    refreshToken = data["refresh_token"];
    idToken = data["id_token"];

    console.log("access_token = " + accessToken);
    console.log("refresh_token = " + refreshToken);
    console.log("id_token = " + idToken);

    // локальное хранилище браузера позволяет сохранить значение, чтобы использовать его даже после перезагрузки страницы
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    localStorage.setItem(ID_TOKEN_KEY, idToken);


    // получить данные из Resource Server, автоматически сразу после получения access token
    getDataFromResourceServer();

}


// получить данные из Resource Server, добавив в запрос access token
function getDataFromResourceServer() {

    // ajax запрос (параллельный вызов)
    $.ajax({
        beforeSend: function (request) { // обязательные заголовки
            request.setRequestHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
            request.setRequestHeader("Authorization", "Bearer " + accessToken); // задаем Bearer c access token, чтобы Resource Server не отклонил запрос
        },
        type: "GET", // тип запроса (обязательно должен быть get)
        url: RESOURCE_SERVER_URL + "/user/data", // адрес, куда отправляем запрос
        success: resourceServerResponse, // метод для выполнения, если запрос сработает успешно (callback)
        error: resourceServerError, // если запрос завершился ошибкой, вызываем другую функцию
        dataType: "text" // в каком формате ожидаем ответ от auth server (в нашем случае это обычный текст - для упрощения, но чаще всего это JSON)
    });
}

// обработка "успеха" от resource server (callback)
function resourceServerResponse(data, status, jqXHR) { // эти параметры передаются автоматически

    // каким образом отображать данные на странице - уже зависит от требований и технологий
    document.getElementById("userdata").innerHTML = data;
    console.log("resource server data = " + data);

}


// обработка ошибки от resource server (callback)
function resourceServerError(request, status, error) {

    // сам json
    var json = JSON.parse(request.responseText); // JSON.parse преобразовывает из текста в объект JSON

    // можно получить из json любое значение
    var errorType = json["type"];

    console.log(errorType);

    // пытаемся сначала получить refresh token из localStorage
    refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);

    // если есть refresh token
    if (refreshToken) {
        // получаем новый access token с помощью него (т.е.не запускаем полный цикл PKCE, где пользователю нужно вводить логин-пароль)
        exchangeRefreshToAccessToken();

    } else { // если нету refresh token - запускаем полный цикл PKCE с вводом логина-пароля
        initAccessToken(); // минус этого решения - нужно будет заново вводить логин-пароль
    }

}

// запрос на новый access token используя refresh token
// в ответе будет как новый AT, так и новый RT
function exchangeRefreshToAccessToken() {

    console.log("new access token initiated");

// набор параметров для правильного обращения к auth server
    var data = {
        "grant_type": GRANT_TYPE_REFRESH_TOKEN, // уведомляем auth server, что мы хотим получить новый access token, используя refresh token
        "client_id": CLIENT_ID, // берем из KeyCloak
        "refresh_token": refreshToken // текущий refresh token
    };

    $.ajax({ // ajax запрос для параллельного вызова
        beforeSend: function (request) { // обязательные заголовки
            request.setRequestHeader("Content-type", "application/x-www-form-urlencoded; charset=UTF-8");
        },
        type: "POST", // тип запроса обязательно должен быть POST
        url: KEYCLOAK_URI + "/token", // адрес обращения
        data: data, // параметры запроса
        success: accessTokenResponse, // (callback) какой метод вызывать после выполнения запроса (туда будет передан результат)
        error: exchangeRefreshError,
        dataType: "json" // в каком формате получаем ответ от auth server
    });
}

// в случае ошибки при обмене RT на AT - просто заново просим пользоваля авторизоваться, чтобы получить новые значения
function exchangeRefreshError(request, status, error) {
    logout();
}


// войти в систему - получить access token одним из способов
function login() {
    if (refreshToken) {
        exchangeRefreshToAccessToken();  // получить новые токены без ввода логина-пароля
    } else {
        initAccessToken(); // получить новые токены с вводом логина-пароля
    }

    getDataFromResourceServer();
}


// выйти из системы - удалить все токены
function logout() {

    var idToken = localStorage.getItem(ID_TOKEN_KEY);

    console.log("logout");

    // в каждой версии KeyCloak может изменяться URL - поэтому нужно сверяться с документацией
    var authUrl = KEYCLOAK_URI + "/logout";

    authUrl += "?post_logout_redirect_uri=" + CLIENT_ROOT_URL; // уведомляем auth server, что мы хотим получить новый access token, используя refresh token
    authUrl += "&id_token_hint=" + idToken; // данные о пользователе
    authUrl += "&client_id=" + CLIENT_ID; // название клиента из KeyCloak


    // открываем окно для авторизации в этом же окне (self)
    window.open(authUrl, '_self');


    // очищаем все старые значения
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(ID_TOKEN_KEY);

    accessToken = "";
    refreshToken = "";

}
