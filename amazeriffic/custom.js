var main = function () {
    "use strict";

    var toDos = [
        "Finish writing this book",
        "Take Gracie to the park",
        "Answer emails",
        "Prep for Monday's class",
        "Make up some new ToDos",
        "Get Groceries"
    ];
};
       $(element).on("click", function () {
            var $element = $(element);
                $content;

            $(".tabs a span").removeClass("active");
            $element.addClass("active");
            $("main .content").empty();

            if ($element.parent().is(":nth-child(1)")) {
                console.log(" First tab clicked");
            } else if ($element.parent().is(":nth-child(2)")) {
                $content = $("<ul>");
                toDos.forEach(function (todo) {
                    $content.append($("<li>").text(todo));
                });
                $("main .content").append($content);
            } else if ($element.parent().is(":nth-child(3)")) {
                console.log(" Third tab clicked");
            }
       });