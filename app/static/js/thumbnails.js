/* global app */

app.factory('thumbnails', ['$http', function($http) {
  // Fetch JSON from server using HTTP GET request
  return $http.get('https://info3180-project2-simonerscott.c9users.io/api/thumbnails') 
            .then(function(response) { 
              // Thumbnail data
              console.log(response.data);
              return response.data; 
            } 
            ,function(err) { 
              // Error info
              return err; 
            }); 
}]);