// find the elements on the page
/* var result = document.getElementById("result");
if (Modernizr.draganddrop) {
	result.innerHTML = "rejoice, your browser supports drag-and-drop.";
}
else {
	result.innerHTML = "your feeble browser doesn't support drag-and-drop";
}
*/

function validateComments(input) {
	if (input.value.length < 20) {
		input.setCustomValidity("You need to comment in more detail.");
	}
	else {
		// there's no error. Clear any error message
		input.setCustomValidity("");
	}
}
	