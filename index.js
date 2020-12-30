'use strict'

//ID USUARIO NO EXISTENTE, PETA

//reservas

//api pago

//falta validar body de idProveedores o sino mirar si puedo sincronizar la bbdd con una de mi maquina.
//actualizar apis a partir de la de vuelo

const port = process.env.PORT || 3100;
const URL_WS_VUELO = 'https://localhost:3000/api'; //VUELO
const URL_WS_VEHICULO = 'https://localhost:3001/api';
const URL_WS_HOTEL = 'https://localhost:3002/api';

const https = require('https');
const fs = require('fs');

const OPTIONS_HTTPS = {
    key: fs.readFileSync('./cert/key.pem'),
    cert: fs.readFileSync('./cert/cert.pem') 
};

const agent = new https.Agent({
    rejectUnauthorized: false
  })

const express = require('express');
const logger = require('morgan');
const fetch = require('node-fetch');
const mongojs = require('mongojs');
const { json } = require('express');
const bcrypt = require('bcrypt');
const { create } = require('domain');

const TokenService = require('./tokens');
const moment = require('moment');

const app = express();

var db = mongojs('mongodb+srv://urrea:1234@cluster0.p84hz.mongodb.net/agencia?retryWrites=true&w=majority');
var id = mongojs.ObjectID;

//Declaramos los middleware
app.use(logger('dev'));
app.use(express.urlencoded({extended:false}));
app.use(express.json());

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; //Así resolvemos el error self-signed certificate


app.param("colecciones", (request,response,next,colecciones)=>{
    console.log('middleware param /api/:colecciones');
    request.collection =db.collection(colecciones);
    return next();
});

function auth(request,response,next){
    //encontrar el token de la bbdd
    


    if(!request.params.id){
        response.status(401).json({
            result: 'KO',
            mensaje: "No se especifica la id del usuario que realiza la llamada"
        })
        return next(new Error("Falta id usuario"));
    }

    //const queToken;
    var collection = db.collection("usuarios");
    collection.findOne({_id: id(request.params.id)},(err,elemento)=>{
        if(err) response.json(`Id: ${request.params.id}, no válida`);

        console.log(elemento);
        //queToken = elemento.token;
        TokenService.decodificaToken(elemento.token)
        .then(userId =>{
            console.log(`Usuario con ID: ${userId} autorizado`);
            //request.params.token = elemento.token;
            //return next();
        })
        .catch(err => response.status(401).json({
            result: 'KO', 
            mensaje: "Error autorizacion: Token caducado, debe identificarse nuevamente"
        })
        );
      //  return next(new Error("Acceso no autorizado"));
    }); 


    if(!request.headers.authorization){
        response.status(401).json({
            result: 'KO',
            mensaje: "No se ha enviado el token tipo Bearer en la cabecera Authorization"
        })
        return next(new Error("Falta token de autorizacion"));
    }

    const queToken = request.headers.authorization.split(" ")[1];
    if(queToken === "MITOKEN123456789"){  //JWT
        request.params.token = queToken;  //Creamos nueva propiedad para propagar el token
        return next();
    }

    response.status(401).json({
        result: 'KO',
        mensaje: "Acceso no autorizado a este servicio"
    });
    return next(new Error("Acceso no autorizado"));
}

function isProveedor(request, response, next){

    const queProveedor = request.params.proveedores;

    var queURL = ``;

    switch(queProveedor){
        case "vuelo":
            queURL  = `${URL_WS_VUELO}`;
            break;
        case "vehiculo":
            queURL  = `${URL_WS_VEHICULO}`;
            break;
        case "hotel":
            queURL  = `${URL_WS_HOTEL}`;
            break;
        default:
            response.json(`End-Point inválido: ${queProveedor} no existe`);
    }

    if(request.params.colecciones){
        queURL += `/${request.params.colecciones}`;
    }

    if(request.params.reserva){
        queURL += `/${request.params.reserva}`;
    }

    /*if(!request.params.idProveedor){
        
    }else{
        if(request.params.id){
            queURL += `/${request.params.id}`;
        }
    }*/
    if(request.params.idProveedor){
        queURL += `/${request.params.idProveedor}`;
    }

    console.log(queURL);
    return queURL;
}
////////////////////////////////////////////////////
////////////////////////////////////////////////////
//TOKENS



//GENERACION HASH Y SALT
function createHashSalt(request, response, next){
  
    bcrypt.hash(request.body.password, 10, (err, hash) => {
        if(err) console.log(err)
        else{
            console.log(`Hash = ${hash}`);
            request.body.password = hash;
            var collection = db.collection("usuarios");
            collection.save({user: request.body.user,password: hash, token: null}, (err, elementoGuardado) =>{
                if (err) return next(err);
        
                console.log(elementoGuardado);
                response.status(201).json({
                    result: 'OK',
                    elemento: elementoGuardado
                });
            });
        }
    });

}

function verifyPassword(hash, request, response, next){


    bcrypt.compare(request.body.password, hash, (err, result) => {
        console.log(`${hash}`);
        console.log(`Result: ${result}`);

        if(result)
            console.log(`Contraseña correcta`);
        else
            response.json(`Contraseña inválida`);
    });
}

app.post('/api/registrar', (request, response, next) => {

    const user = request.body;
    
    createHashSalt(request, response, next);

});

app.get('/api/identificar/:id', (request, response, next) => {

    const queID = request.params.id;
    var hash = ``;
    var collection = db.collection("usuarios");
    collection.findOne({_id: id(queID)},(err,elemento)=>{
        if(err) response.json(`Id: ${queID}, no válida`);

        console.log(elemento);
        hash = elemento.password;
        verifyPassword(hash, request,response,next);
    }); 

   
    //Creamos un token
    const token = TokenService.creaToken(request.params.id);

    console.log(token);
    console.log(`Usuario y contraseña correctos`);
    //Decodificar un token
    TokenService.decodificaToken(token)
        .then(userId =>{
            console.log(`Usuario con ID: ${userId} autenticado y autorizado correctamente`);
        })
        .catch(err => response.json(`Token caducado`));

    var collection = db.collection("usuarios");//guardar por id
    collection.update({_id: id(queID)}, {$set: {token: token}}, function(err, elementoGuardado) {
        if (err || !elementoGuardado) response.json("Usuario no pudo ser autorizado");
        else response.json("Usuario autorizado con nuevo Token");
    });
});

/*bcrypt.hash( password, 10, (err, hash) => {
    if(err) console.log(err)
    else{
        console.log(`Hash = ${hash}`);
        bcrypt.compare(password, hash, (err, result) => {
            console.log(`Result: ${result}`);
        });
    }
});
*/

/////////////////////////////////
/////////////////////////////////
/////////////////////////////////


app.get('/api', (request, response, next) =>{

    response.json( {
        "result": "Ok",
        "proveedores": [
            {
                "nombre": "vuelo"
            },
            {
                "nombre": "vehiculo"
            },
            {
                "nombre": "hotel"
            }
        ]
    });

});

//Declaramos nuestras rutas y nuestros controladores
app.get('/api/:proveedores', (request, response, next) =>{

    var queURL = isProveedor(request,response,next);
    
    fetch( queURL)
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: json.result,
                colecciones: json.colecciones
            });
    });  

});

app.get('/api/:proveedores/:colecciones', (request,response,next) =>{
    const queColeccion = request.params.colecciones;
    var queURL = isProveedor(request,response,next);

    fetch( queURL)
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: json.result,
                colecciones: queColeccion,
                elementos: json.elementos
            });
    });  
});

app.get('/api/:proveedores/:colecciones/:idProveedor', (request,response,next) =>{
    const queColeccion = request.params.colecciones;
    var queURL = isProveedor(request,response,next);

    fetch( queURL )
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: json.result,
                colecciones: queColeccion,
                elemento: json.elementos
            });
    });  
});

///********************** */
///********************** */
///RESERVA
///********************** */
///********************** */


app.post('/api/:proveedores/:colecciones/:id', auth,(request,response,next) => {
    const nuevoElemento = request.body;
    const queColeccion = request.params.colecciones;
   
    const queToken = request.params.token;
    var queURL = isProveedor(request,response,next);
    //const newURL = queURL + `/${idProveedor}`;//para comprobar el proveedor si existe

    /*if(queColeccion == "reserva"){
        
        const idUsuario = request.body.idUsuario;
        const idProveedor =``;

        if(request.body.idVuelo){
            idProveedor = request.body.idVuelo;

        }else{
            if(request.body.idHotel){
                idProveedor = request.body.idHotel;
            }else{
                if(request.body.idVehiculo){
                    idProveedor = request.body.idVehiculo;
                }else{
                    response.json(`Error: formato body no válido -> id(Proveedor): idVuelo, idVehiculo, idHotel.`)
                }
            }
        }


        //buscar en bbdd //5febd75a52c87e6b20984212
        request.collection.findOne({_id: id(idUsuario)},(err,elemento)=>{
            if(err)
                response.json(`Error: id de Usuario no existe`);
            else
                console.log(elemento);
        });
        
        

        fetch( newURL )//5fec66ef70c63c0a55028e49
            .then( response=>response.json() )
            .then( json => {
            response.json(json.elemento);
        });  
    }*/

    fetch( queURL, {
        method: 'POST',
        body: JSON.stringify(nuevoElemento),
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${queToken}`
        }    
    } )
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: 'OK',
                colecciones: queColeccion,
                elemento: json.elemento
            });
    });  

});

app.put('/api/:proveedores/:colecciones/:id/:idProveedor', auth, (request,response,next) =>{
    const nuevoElemento = request.body;
    const queColeccion = request.params.colecciones;
    const queId = request.params.idProveedor;
    var queURL = isProveedor(request,response,next);
    const queToken = request.params.token;

    fetch( queURL, {
        method: 'PUT',
        body: JSON.stringify(nuevoElemento),
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${queToken}`
        }    
    } )
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: 'OK',
                colecciones: queColeccion,
                elemento: nuevoElemento
            });
    });  
});

app.delete('/api/:proveedores/:colecciones/:id/:idProveedor', auth, (request,response,next)=>{
    const queColeccion = request.params.colecciones;
    const queId = request.params.idProveedor;
    var queURL = isProveedor(request,response,next);
    const queToken = request.params.token;

    fetch( queURL, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${queToken}`
        }    
    } )
        .then( response=>response.json() )
        .then( json => {
            //Mi logica de negocio
            response.json( {
                result: 'OK',
                colecciones: queColeccion,
                elemento: json.elemento
            });
    });  
});


https.createServer( OPTIONS_HTTPS, app ).listen(port, () => {
    console.log(`WS API GW del WS REST CRUD ejecutandose en https://localhost:${port}/:colecciones/:id`)
});
/*
app.listen(port, () => {
    console.log(`WS API GW del WS REST CRUD ejecutandose en http://localhost:${port}/:colecciones/:id`)
});*/



