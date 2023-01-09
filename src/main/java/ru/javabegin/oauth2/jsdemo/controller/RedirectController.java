package ru.javabegin.oauth2.jsdemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

// В нашем тестовом примере все логика работы прописана в javascript + HTML
// Поэтому этот контроллер просто обрабатывает запросы от клиента и AuthServer (в нашем случае KeyCloak) и перенправляет на нужные страницы


// !!! Не используем аннотацию @RestController,
// потому что в этом случае он не будет перенаправлять запрос на страницу, а будет сразу возвращать ответ клиенту

@Controller // в этом случаем будет исп-ся переадресация на страницы
public class RedirectController {

 /*
     Важно помнить, что auth server АВТОМАТИЧЕСКИ передает все параметры в ответе (redirect URI),
     которые нужно правильно считать (в нашем случае через javascript) уже на самое веб странице HTML.
     Поэтому в контроллере мы сами никакие параметры не добавляем и не считываем, а просто перенаправляем запросы на страницы
    */

    // стартовая страница
    @GetMapping("/")
    public String index() {
        return "index"; // открываем нужную страницу (HTML или JSP из папки resources/templates)
    }

    // если пользователь успешно авторизовался - сюда AuthServer отправит ответ с параметрами и auth code
    @GetMapping("/redirect") // тип метода (GET) обязательно должен быть таким же, как и отправляет AuthServer
    public String redirect() {
        return "redirect"; // открываем нужную страницу (HTML или JSP из папки resources/templates)
    }

    // обработка результата запроса от Resource Server (с полученным ранее access token)
    // т.е. уже сами бизнес-данные приложения
    @PostMapping("/result") // обязательно POST, потому что ответ от auth server именно в POST
    public String result() {
        return "index";  // открываем нужную страницу (HTML или JSP из папки resources/templates)
    }

}
