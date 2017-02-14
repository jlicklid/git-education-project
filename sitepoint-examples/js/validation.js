function setErrorMessages(formControl) {
	var validityState_object = formControl.validity;
	if (validityState_object.valueMissing) {
		formControl.setCustomValidity('Please set an age (required)');
	} else if (validityState_object.rangeUnderflow) {
		formControl.setCustomValidity('You\'re too young');
	} else if (validityState_object.rangeOverflow) {
		formControl.setCustomValidity('You\'re too old');
	} else if (validityState_object.steMismatch) {
		formControl.setCustomValidity('Counting half birthdays?');
	} else {
		// if valid, must set falsy value or will always create error
		formControl.setCustomValidity('');
	}
}