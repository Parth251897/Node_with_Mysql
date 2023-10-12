const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { StatusCodes } = require("http-status-codes");
const {
  passwordencrypt,
  validatePassword,
} = require("../../services/CommonService");
const responsemessage = require("../../utils/ResponseMessage.json");
const connection = require("../../config/Db.config");
// const uploadFile = require("../../middleware/FileUpload");


exports.SignUp = async (req, res) => {
  let { EmpName, userName, email, phone, password } = req.body;
  try {
    userName = EmpName.toLowerCase() + Math.floor(10 + Math.random() * 100);
    phone = parseInt(phone, 10);

    const checkQuery = "SELECT * FROM employee WHERE email = ? OR phone = ?";
    connection.query(checkQuery, [email, phone], async (error, results) => {
      let existemail = results.find((employee) => employee.email === email);
      let phone = results.find(
        (employee) => employee.phone === parseInt(phone, 10)
      );

      if (existemail || phone) {
        const message = existemail
          ? responsemessage.EMAILEXITS
          : responsemessage.PHONEEXITS;

        res.status(400).json({
          status: StatusCodes.BAD_REQUEST,
          message,
        });
      } else {
        if (!validatePassword(password)) {
          return res.status(400).json({
            status: StatusCodes.BAD_REQUEST,
            message: responsemessage.VALIDATEPASS,
          });
        } else {
          const hashPassword = await passwordencrypt(password);
          const insertQuery =
            "INSERT INTO employee (userName,EmpName, email, phone, password) VALUES (?, ?, ?, ?, ?)";
          connection.query(
            insertQuery,
            [userName, EmpName, email, phone, hashPassword],
            (error, insertResults) => {
              if (error) {
                return res.status(400).json({
                  status: StatusCodes.BAD_REQUEST,
                  message: responsemessage.NOTCREATED,
                });
              } else {
                return res.status(201).json({
                  status: StatusCodes.CREATED,
                  message: responsemessage.CREATED,
                });
              }
            }
          );
        }
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.UserFind = async (req, res) => {
  try {
    let { id } = req.body;

    const selectdata = "SELECT * FROM employee WHERE id = ?";
    connection.query(selectdata, [id], async (error, results) => {
      if (error) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      } else {
        res.status(200).json({
          status: StatusCodes.OK,
          results,
          message: responsemessage.FOUNDUSER,
        });
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.UserFindAll = async (req, res) => {
  try {
    let userId = req.currentUser;

    const selectdata = "SELECT * FROM employee";
    connection.query(selectdata, (error, results) => {
      if (error) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      } else {
        res.status(200).json({
          status: StatusCodes.OK,
          results,
          message: responsemessage.FOUNDUSER,
        });
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.UserUpdate = async (req, res) => {
  try {
    let { EmpName,email, phone } = req.body;

    let { id } = req.body;

    const selectQuery = "SELECT * FROM employee WHERE id = ?";

    connection.query(selectQuery, [id], async (error, results) => {
      if (error) {
        return res.status(400).json({
          status: StatusCodes.BAD_REQUEST,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const existingUser = results[0];
        const checkQuery =
          "SELECT * FROM employee WHERE email = ? OR phone = ?";

        connection.query(checkQuery, [email, phone], async (error, results) => {
          let existemail = results.find((employee) => employee.email === email);

          const phone = results.find(
            (employee) => employee.phone === parseInt(phone, 10)
          );

          if (existemail || phone) {
            const message = existemail
              ? responsemessage.EMAILEXITS
              : responsemessage.phoneEXITS;

            res.status(400).json({
              status: StatusCodes.BAD_REQUEST,
              message,
            });
          } else {
            // const useremail = email ? email.toLowerCase() : undefined;

            const updatedatas = [];
            const updateValues = [];

            if (email) {
              updatedatas.push("email = ?");
              updateValues.push(email.toLowerCase());
            }
            if (phone) {
              updatedatas.push("phone = ?");
              updateValues.push(parseInt(phone, 10));
            }
            if(EmpName){
              updatedatas.push("EmpName = ?");
              updateValues.push(EmpName);
            }

            if (updatedatas.length === 0) {
              return res.status(404).json({
                status: StatusCodes.NOT_FOUND,
                message: responsemessage.NOTFOUND,
              });
            } else {
              const updateQuery = `UPDATE employee SET ${updatedatas.join(
                ", "
              )} WHERE id = ?`;
              updateValues.push(id);

              connection.query(updateQuery, updateValues, (error) => {
                if (error) {
                  return res.status(400).json({
                    status: StatusCodes.BAD_REQUEST,
                    message: responsemessage.NOTUPDATE,
                  });
                }

                res.status(200).json({
                  status: StatusCodes.OK,
                  message: responsemessage.UPDATE,
                });
              });
            }
          }
        });
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.UserDelete = async (req, res) => {
  try {
    let { id } = req.body;

    const selectdata = "SELECT * FROM employee WHERE id = ?";
    connection.query(selectdata, id, async (error, results) => {
      if (error) {
        return res.status(400).json({
          status: StatusCodes.BAD_REQUEST,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const user = results[0];
        console.log(user);
        const updatedata = "UPDATE employee SET isactive = true WHERE id = ?";
        connection.query(updatedata, id, (error) => {
          if (error) {
            return res.status(404).json({
              status: StatusCodes.NOT_FOUND,
              message: responsemessage.NOTFOUND,
            });
          } else {
            return res.status(200).json({
              status: StatusCodes.OK,
              user,
              message: responsemessage.DELETED,
            });
          }
        });
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};

exports.userActive = async (req, res) => {
  try {
    const { id } = req.body;

    if (!id) {
      return res.status(400).json({
        status: StatusCodes.BAD_REQUEST,
        message: responsemessage.NOTEMPTY,
      });
    }

    const selectQuery = "SELECT * FROM employee WHERE id = ?";
    connection.query(selectQuery, [id], async (selectError, [empRows]) => {
      if (selectError) {
        console.error({ selectError });
        return res.status(500).json({
          status: StatusCodes.INTERNAL_SERVER_ERROR,
          message: responsemessage.INTERNAL_SERVER_ERROR,
        });
      }

      if (empRows.length === 0) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      } else {
        const updateQuery = "UPDATE employee SET isactive = ? WHERE id = ?";
        connection.query(updateQuery, [false, id], async (updateError) => {
          if (updateError) {
            console.error({ updateError });
            return res.status(500).json({
              status: StatusCodes.INTERNAL_SERVER_ERROR,
              message: responsemessage.INTERNAL_SERVER_ERROR,
            });
          }

          return res.status(200).json({
            status: StatusCodes.OK,
            message: responsemessage.USERACTIVE,
          });
        });
      }
    });
  } catch (error) {
    console.error({ error });
    res.status(304).json({
      status: StatusCodes.NOT_MODIFIED,
      message: responsemessage.NOT_MODIFIED,
    });
  }
};

exports.UserDeleteAccount = async (req, res) => {
  try {
    let {id} = req.body;

    const selectdata = "SELECT * FROM employee WHERE id = ?";
    connection.query(selectdata, [id], async (error, results) => {
      if (error) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      }
      if (results.length === 0) {
        return res.status(404).json({
          status: StatusCodes.NOT_FOUND,
          message: responsemessage.NOTFOUND,
        });
      }

      const user = results[0];

      const deletedata = "DELETE FROM employee WHERE id = ?";
      connection.query(deletedata, [id], (error) => {
        if (error) {
          return res.status(404).json({
            status: StatusCodes.NOT_FOUND,
            message: responsemessage.NOTFOUND,
          });
        } else {
          return res.status(200).json({
            status: StatusCodes.OK,
            user,
            message: responsemessage.DELETED,
          });
        }
      });
    });
  } catch (error) {
    return res.status(500).json({
      status: StatusCodes.INTERNAL_SERVER_ERROR,
      message: responsemessage.INTERNAL_SERVER_ERROR,
    });
  }
};
