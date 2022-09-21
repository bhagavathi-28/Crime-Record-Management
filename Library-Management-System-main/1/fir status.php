<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width ,initialisation-scale=1"><!-- not clear-->
<meta http-equiv="X-UA-Compatible" content="IE=edge"><!--i donot know-->
  <title>fir status</title>
  
  <link rel="stylesheet" href="bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="fir status.css">
  <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.0/css/all.css" integrity="sha384-lZN37f5QGtY3VHgisS14W3ExzMWZxybE1SJSEsQp9S+oqd12jhcu+A56Ebc1zFSJ" crossorigin="anonymous">

<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  
</head>
<body>
<header class="box1">
   <nav id="header-nav" class="navbar navbar-default">
    <div class="container">

      <div class="navbar-header">
        <div class="navbar-brand">
        <a href="#">
                  <h1>Crime record management system</h1>
                </a>
              </div>
      </div>
     <div id="collapsable-nav" class="collapse navbar-collapse">
      <ul id="nav-list" class="nav navbar-nav navbar-right">
   <button class="btn btn-light dropdown-toggle" type="button" data-toggle="dropdown"><i class="fas fa-user"></i>
    <span class="caret"></span></button>
    <ul class="dropdown-menu">
      <li><a href="homepage citizen.php">Home</a></li>
      <li class="divider"></li>
      <li><a href="homepage citizen.php?logout=1" >Sign out</a></li>
      </ul>
        </ul>
    </div>
   
    </div>
   </nav>
    
    
  </header>
   <div class="forms">
    <form class="loginbox"  >
      <h1>View fir</h1>
      <div class="table-box">
      
        <div class="table-row table-head" >
            <div class="table-cell first-cell" >
                <p>S no.</p>
            </div>
            <div class="table-cell">
                <p>FIR no.</p>
            </div>
            <div class="table-cell long" >
                <p>Name</p>
            </div> 
            <div class="table-cell">
                <p>Phone number</p>
            </div>
            <div class="table-cell long">
                <p>Email</p>
            </div>
            <div class="table-cell long">
                <p>FIR date</p>
            </div>
            <div class="table-cell long">
                <p>Status</p>
            </div>
            
        </div>


        <div class="table-row">
            <div class="table-cell first-cell">
                <p>1</p>
            </div>
            <div class="table-cell ">
                <p>93810604311111</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
            <div class="table-cell">
                <p>919381060431</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
              
        </div>


        <div class="table-row">
            <div class="table-cell first-cell">
                <p>2</p>
            </div>
            <div class="table-cell">
                <p>xxx</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
            <div class="table-cell ">
                <p>xxx</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
            <div class="table-cell long">
                <p>xxx</p>
            </div>
              
        </div>
        
        
</div>
      
        
      </form>

    
</div>
    
   
  <footer>
    <div class="container" id="footer">
      <div class="row" >
        
        <section id="hours" class="col-sm-4">
          <span>National emergency number:</span><br>
          <i class="fa fa-phone"></i>: 112<br>
          <hr class="visible-xs">
        </section>
        <section id="hours" class="col-sm-4">
          <span>Police:</span><br>
          <i class="fa fa-phone"></i>: 100<br>
          <hr class="visible-xs">
        </section>
        <section id="hours" class="col-sm-4">
          <span>Women helpline:</span><br>
          <i class="fa fa-phone"></i>: 1091<br>
          <hr class="visible-xs">
        </section>
      </div>
      
    </div>
  </footer>
</body>

</html>