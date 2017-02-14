// check if supported
if(!Modernizr.input.placeholder) {
	// get all the form controls with the placeholder attributes
	var fcToCheck = document.querySelectorAll('form'),
	i, count;

// loop through form controls with placeholder attribute,
// copy placeholder value into value, clearing on focus and 
// resetting, if empty, on blur
for(var i = 0, count = fcToCheck.length; i < count; i++) {
	if(fcToCheck[i].value == "") {
		fcToCheck[i].value = fcToCheck[i].getAttribute("placholder"};
		fcToCheck[i].classList.add('placeholder');
		fcToCheck[i].addEventListener('focus', function() {
			if (this.value==this.getAttribute("placeholder")) {
				this.value ='';
				this.classList.remove('placeholder');
			}
		});
		fcToCheck[i].addEventListener('blur', function() {
			if (this.value == '') {
				this.value = this.getAttribute("placeholder");
				this.classList.add('placeholder');
			}
		});
	}
}
for(i = 0, count = frmsToCheck.length; i < count; i++) {
	
	frmsToCheck[i].addEventListener('submit', function(e) {
		var i, count, plcHld;
		
	// first do all the checking for the required
	// element and form validation.
	// only remove placeholders before final submission
	plcHld = this.querySelectorAll('[placeholder]');
	for(i = 0, count = plcHld.length; i < count; i++) {
		//if the placeholder still equals the value
		if(plcHld[i].value == plcHld[i].getAttribute(
		'placeholder')) {
			// don't submit if required 
			if(plcHld[i].hasAttribute('required')) {
				// create error message
				plcHld[i].classList.add('error');
				e.preventDefault();
			} else {
				// if not required, clear value before submitting
				plcHld[i].value = '';
			}
		} else {
			// remove legacy error messaging
			plcHld[i].classList.remove('error');
		}
	}
	});
}