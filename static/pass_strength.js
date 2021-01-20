const PASSWORD_STRENGTH = Object.freeze({
	WEAK: 0,
	AVERAGE: 1,
	STRONG: 2
})

var passwordInput = document.getElementById("pass")
passwordInput.addEventListener("change", checkPasswordStrength)

function checkPasswordStrength(ev)
{
	var passwordInput = ev.target
	var passInfo = document.getElementById("pass_info")
	var ent = entropy(passwordInput.value)

	var passStrength = checkEntropy(ent)
	switch(passStrength)
	{
		case PASSWORD_STRENGTH.WEAK:
			passInfo.innerText = "Siła hasła: slabe (wysokie prawdopodobieństwo kradzieży hasła)"
			//passInfo.className = "weak"
			break;
		case PASSWORD_STRENGTH.AVERAGE:
			passInfo.innerText = "Siła hasła: przecietne"
			//passInfo.className = "average"
			break;
		case PASSWORD_STRENGTH.STRONG:
			passInfo.innerText = "Siła hasła: silne"
			//passInfo.className = "strong"
			break;
		default:
			passInfo.innerText = "Siła hasła:"
	}
}


function entropy(txt)
{
	var alphlen = 0;
	
	if(RegExp('[0-9]').test(txt)){
		alphlen += 10 
	}
	
	if(RegExp('[a-z]').test(txt)){
		alphlen += 26
	}
	
	if(RegExp('[A-Z]').test(txt)){
		alphlen += 26 
	}
	
	if(RegExp('[^a-zA-Z0-9]').test(txt)){
		alphlen += 33 
	}
	
	return txt.length * Math.log2(alphlen)
}

function checkEntropy(entropy)
{
	if(entropy < 45.0)
		return PASSWORD_STRENGTH.WEAK
	else if(entropy < 60)
		return PASSWORD_STRENGTH.AVERAGE
	else
		return PASSWORD_STRENGTH.STRONG
}