document.addEventListener("contextmenu", function (event) {
  event.preventDefault(); // Prevent the default context menu from showing up
  var targetElement = event.target.closest('.client_id'); // Attempt to find the closest parent with the class 'client_id'
  if (!targetElement) {
      // If no direct match, try finding the closest td element and then check if it has a sibling with the class 'client_id'
      targetElement = event.target.closest('td').nextSibling;
      if (targetElement && targetElement.classList.contains('client_id')) {
          targetElement = event.target.closest('td');
      }
  }
  if (targetElement) { // Check if the target element exists
      var client_id = targetElement.textContent || targetElement.innerText; // Get the text content of the element
      console.log(client_id); // Log the client_id to the console
  }
  var menu = document.getElementById("custom-context-menu");
  menu.style.display = "block";
  menu.style.left = event.pageX + "px";
  menu.style.top = event.pageY + "px";
});

document.addEventListener("click", function () {
  var menu = document.getElementById("custom-context-menu");
  menu.style.display = "none";
});
