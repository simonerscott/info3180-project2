// Your JavaScript Code here
var app = angular.module("MyApp", []);


app.controller("loginCtrl", function($scope, $http){
    $scope.token = '';
    $scope.login = function(){
        var uname = document.getElementById("username").value;
        var passw = document.getElementById("password").value;
        
        var data = {username: uname, password: passw};
        
        $http.post('/api/users/login', JSON.stringify(data)).then(function(response){
            if (response["status"] == 200){
                //let token = response.data.data.token;
                let token = response.data.token;
                let user = response.data.user.id;
                //alert(token);
                localStorage.setItem('token', token);
                localStorage.setItem('user', user);
                $scope.token = token;
                window.location = '/wishlist';
            }
            else{
                alert("404 Not OK ");
            }
        });
    }
});



app.controller("registerCtrl", function($scope, $http){
    
    $scope.register = function(){
        var fname = document.getElementById("firstname").value;
        var lname = document.getElementById("lastname").value;
        var uname = document.getElementById("username").value;
        var passw = document.getElementById("password").value;
        var email = document.getElementById("email").value;
        var confirmPassword = document.getElementById("confirmPassword").value;
        if (passw == confirmPassword){
          var data = {firstname: fname, lastname: lname, username: uname, password: passw, email:email};
    
          $http.post('/api/users/register', JSON.stringify(data)).then(function(res){
            if (res["status"] == 200){
                window.location = '/login';
            }
            else{
                alert("404 Not OK ");
            }
        });
        }
        else{
          alert("Wrong password")
        }
        
        
    };
});

app.controller('WishCtrl' ,function ($scope,$http) {
	
  var userid= localStorage.getItem('user');
	$http.get('/api/users/'+userid+'/wishlist')
        .success(function(data) {
        	$scope.wishes = data.wishes;

        	$log.log($scope.wishes);
        	
      })
        .error(function(error) {
        $log.log(error);
      });
        

   $scope.delete = function() {
   
      $http.post('/api/users/'+ userid +'/wishlist/' + this.wish.id)
      .success(function(data) {
        if (data.message == 'Success') {
        alert("worked")
      }else if(data.message == 'Failed'){
        alert("failed");
      }
      })
     .error(function(error) {
          alert("failed");
      })
   };






});

