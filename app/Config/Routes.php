<?php

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */
$routes->get('/', 'Home::index');


$routes->post('get-availabilities', 'ApiController::sendAvailability');
$routes->get('get-availabilities', 'ApiController::sendAvailability'); // optional for GET
