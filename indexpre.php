<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="navbar.css">
  <title>SCANIA</title>
</head>
<body>
  <header>
    <div class="logo">SCANIA</div>
    <div class="hamburger">
        <div class="line"></div>
        <div class="line"></div>
        <div class="line"></div>
    </div>
    <nav class="nav-bar">
      <ul>
        <li>
          <a href="Login.html">Sign in</a>
        </li>
        <li>
          <a href="Login.html">Sign up</a>
        </li>
      </ul>
    </nav>
  </header>
      <div class="video-container">
        <video src="images/Scania.MOV" type="video/MOV" autoplay loop muted>
        </video>
      </div> 
    <div class="footer">
      <div class="footer-el">
        <h3>Our Services</h3>
        <ul>
          <li>State of the art diagnostic tool</li>
          <li>Information on pneumonia</li>
          <li>Symptom checker</li>
          <li>Treatment options</li>
        </ul>
      </div>
      <div class="footer-el">
        <h3>Testimonials</h3>
        <p>"Thanks to Scania - Pneumonia Detection, I was able to detect my pneumonia early and get the treatment I needed"<br><br> "The diagnostic tool on Scania - Pneumonia Detection was incredibly accurate and easy to use.Highly recommended"</p>
       
      </div>
    </div>
  <script>
    hamburger = document.querySelector(".hamburger");
    hamburger.onclick = function() {
      navBar = document.querySelector(".nav-bar");
      navBar.classList.toggle("active");
    }
  </script>
</body>
</html>