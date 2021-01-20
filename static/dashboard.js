var addButton = document.getElementById("addButton")
addButton.addEventListener("click", (ev) => {
	window.location.href = "/dashboard/new"
	})
	
var tab = document.getElementById("tab")
var rowsNumber = tab.children[0].children.length
const passwordCol = 1
const deleteButtonColNumber = 2
const decryptPassButtonColNumber = 3
const copyButtonColNumber = 4

for(var i = 1; i < rowsNumber; i++) {
	var row = tab.children[0].children[i]
	var deleteButton = row.children[deleteButtonColNumber].children[0]
	deleteButton.addEventListener("click", deleteRowData)
	var decryptPassButton = row.children[decryptPassButtonColNumber].children[0]
	decryptPassButton.addEventListener("click", decryptPassword)
	
}

function deleteRowData(ev)
{
	var pid = ev.target.parentNode.parentNode.id
	var endpoint = "https://localhost:443/dashboard/" + pid
	var xhr = new XMLHttpRequest()
	xhr.open('DELETE', endpoint)
	xhr.onreadystatechange = function() {
		location.reload()
	}
	xhr.send(null);
}

function decryptPassword(ev)
{
	var pid = ev.target.parentNode.parentNode.id
	var passCol = ev.target.parentNode.parentNode.children[passwordCol]
	var endpoint = "https://localhost:443/dashboard/" + pid + "?encode=false"
	var xhr = new XMLHttpRequest()
	xhr.open('GET', endpoint)
	xhr.onreadystatechange = function() 
	{
		var DONE = 4;
		var OK = 200;
		if (xhr.readyState == DONE) 
		{
			if (xhr.status == OK) 
			{
				passCol.innerText = xhr.responseText
				ev.target.innerHTML = "Zaszyfruj"
				ev.target.removeEventListener("click", decryptPassword)
				ev.target.addEventListener("click", encryptPassword)
				addCopyButton(ev.target.parentNode.parentNode)
			}
		}
	}
	xhr.send(null);
}

function encryptPassword(ev)
{
	var pid = ev.target.parentNode.parentNode.id
	var passCol = ev.target.parentNode.parentNode.children[passwordCol]
	var endpoint = "https://localhost:443/dashboard/" + pid + "?encode=true"
	var xhr = new XMLHttpRequest()
	xhr.open('GET', endpoint)
	xhr.onreadystatechange = function() 
	{
		var DONE = 4;
		var OK = 200;
		if (xhr.readyState == DONE) 
		{
			if (xhr.status == OK) 
			{
				passCol.innerText = xhr.responseText
				ev.target.innerHTML = "Odszyfruj"
				var decryptPassButton = row.children[decryptPassButtonColNumber].children[0]
				ev.target.removeEventListener("click", encryptPassword)
				ev.target.addEventListener("click", decryptPassword)
				removeCopyButton(ev.target.parentNode.parentNode)
			}
		}
	}
	xhr.send(null);
}

function addCopyButton(row)
{
	var col = document.createElement("td")
	var copyButton = document.createElement("button")
	copyButton.innerHTML = "Kopiuj"
	copyButton.addEventListener("click", copyToClipboard)
	
	col.appendChild(copyButton)
	row.appendChild(col)
}

function removeCopyButton(row)
{
	copyButtonCol = row.children[copyButtonColNumber]
	row.removeChild(copyButtonCol)
}

function copyToClipboard(ev)
{
	var txt = ev.target.parentNode.parentNode.children[passwordCol].innerText
	navigator.clipboard.writeText(txt)
}
