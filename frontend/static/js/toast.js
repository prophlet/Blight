function launch_toast(description, iconClass) {
    // Create a new toast element
    var toast = document.createElement('div');
    toast.id = "toast";
    toast.className = "toast";
   
    // Create the icon element
    var img = document.createElement('div');
    img.id = "img";
    img.className = "info";
    var icon = document.createElement('i');
    icon.className = "icon " + iconClass;
    img.appendChild(icon);
    toast.appendChild(img);
   
    // Create the description element
    var desc = document.createElement('div');
    desc.id = "desc";
    desc.textContent = description;
    toast.appendChild(desc);
   
    // Append the new toast to the container
    var container = document.getElementById("toast-container");
    container.appendChild(toast);
   
    // Show the toast
    toast.className += " show";
   
    setTimeout(function () {
       // Hide the toast after 5 seconds
       toast.className = toast.className.replace("show", "");
       // Remove the toast from the DOM after hiding
       setTimeout(function() {
         container.removeChild(toast);
       }, 500); // Adjust the timeout to match the fadeout animation duration
    }, 5000);
   }