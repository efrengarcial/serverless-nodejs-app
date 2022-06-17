// import AWS Lambda types
import { APIGatewayEvent, Context } from 'aws-lambda';
// import Lambda API default function
import createAPI, { Request,Response, NextFunction } from 'lambda-api';
import * as yup from 'yup';


// instantiate framework
const api = createAPI(
  {
    logger: {
      level: 'debug',
      access: true,
      customKey: 'detail',
      messageKey: 'message',
      timestamp: () => new Date().toUTCString(), // custom timestamp
      stack: true,
    },
  }
);


const errorHandler = (err, req: Request,res: Response,next: NextFunction) => {
  // do something with the error
  console.log("******************************************************")
  console.log(err);
  res.status(400).send({ "message": err.name , "errors" : err.errors});// .error(400, err, err);
  
};

api.use(errorHandler);


// Define a route
api.get('/status', async (req: Request,res: Response) => {
  req.log.debug('debug log message');
  return { status: 'ok' };
});

const linkSchema = yup.object({
  body: yup.object({
    url: yup.string().url().required(),
    title: yup.string().min(8).max(32).required(),
    content: yup.string().min(8).max(255).required(),
    contact: yup.string().email().required(),
  }),
  params: yup.object({
    id: yup.number().required(),
  }),
});

const validate = (schema) => async (req: Request,res: Response,next: NextFunction) => {
  try {    
    console.log(req.body);
    console.log("*****************************");
    const result = await schema.validate({
      body: req.body,
      query: req.query,
      params: req.params,
    },  { abortEarly: false });
    console.log(result);
    console.log("*****************************");
    next();
  } catch (err) {
    console.log(err);
    return res.error(err);
  }
};

// Define a route
api.post('/error/:id', validate(linkSchema), async (req: Request,res: Response) => {

 /* try {
    await schema.validate({ name: 'jim', age: 11 }, { abortEarly: false })
    
  } catch (error) {
  
    return res.error(error)
    //return res.status(401).error("error",error);
  }*/
  
  return { status: 'ok' };
  
  /*.catch(function (err) {
    console.log(err.name); // => 'ValidationError'
    console.log(err.errors); // => [{ key: 'field_too_short', values: { min: 18 } }]
    return res.error(401, 'unauthorized');
  }); */
  /*console.log("-------------------------------------------------")
  console.log(result.name);
  console.log(result.errors);
  return res.status(401).error("error", result.errors);*/
});


// Declare your Lambda handler
module.exports.server = async (event: APIGatewayEvent, context: Context) => {
  // Run the request
  return await api.run(event, context);
};
